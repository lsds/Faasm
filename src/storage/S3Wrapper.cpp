#include <aws/s3/S3Errors.h>
#include <storage/S3Wrapper.h>

#include <faabric/util/bytes.h>
#include <faabric/util/logging.h>

#include <aws/s3/model/CreateBucketRequest.h>
#include <aws/s3/model/DeleteObjectRequest.h>
#include <aws/s3/model/GetObjectRequest.h>
#include <aws/s3/model/ListObjectsRequest.h>
#include <aws/s3/model/PutObjectRequest.h>

namespace storage {

static Aws::SDKOptions options;

std::shared_ptr<Aws::Auth::AWSCredentialsProvider> getCredentialsProvider()
{
    return Aws::MakeShared<Aws::Auth::ProfileConfigFileAWSCredentialsProvider>(
      "local");
}

Aws::Client::ClientConfiguration getClientConf(long timeout)
{
    Aws::Client::ClientConfiguration config;

    config.region = Aws::String("");
    config.verifySSL = false;
    config.endpointOverride = Aws::String(MINIO_URI);
    config.scheme = Aws::Http::Scheme::HTTP;
    config.connectTimeoutMs = MINIO_CONNECT_TIMEOUT_MS;
    config.requestTimeoutMs = timeout;

    return config;
}

void initSDK()
{
    SPDLOG_INFO("Initialising AWS SDK");
    Aws::InitAPI(options);
}

void cleanUpSDK()
{
    Aws::ShutdownAPI(options);
}

// Note the flag passed to the client for useVirtualAddressing
// https://github.com/aws/aws-sdk-cpp/issues/587
S3Wrapper::S3Wrapper()
  : clientConf(getClientConf(S3_REQUEST_TIMEOUT_MS))
  , client(Aws::Auth::AWSCredentials(MINIO_USER, MINIO_PASSWORD),
           clientConf,
           Aws::Client::AWSAuthV4Signer::PayloadSigningPolicy::Never,
           true)
{}

void S3Wrapper::createBucket(const std::string& bucketName)
{
    SPDLOG_DEBUG("Creating bucket {}", bucketName);
    Aws::S3::Model::CreateBucketRequest request;
    request.SetBucket(bucketName);

    auto response = client.CreateBucket(request);

    if (!response.IsSuccess()) {
        const auto& err = response.GetError();

        auto errType = err.GetErrorType();
        if (errType == Aws::S3::S3Errors::BUCKET_ALREADY_OWNED_BY_YOU ||
            errType == Aws::S3::S3Errors::BUCKET_ALREADY_EXISTS) {
            SPDLOG_DEBUG("Bucket already exists {}", bucketName);
        } else {
            handleError(err);
        }
    }
}

std::vector<std::string> S3Wrapper::listKeys(const std::string& bucketName)
{
    SPDLOG_DEBUG("Listing keys in bucket {}", bucketName);
    Aws::S3::Model::ListObjectsRequest request;
    request.SetBucket(Aws::String(bucketName));

    auto response = client.ListObjects(request);

    if (!response.IsSuccess()) {
        const auto& err = response.GetError();
        handleError(err);
    }

    Aws::Vector<Aws::S3::Model::Object> keyObjects =
      response.GetResult().GetContents();

    std::vector<std::string> keys;
    for (auto const& keyObject : keyObjects) {
        const Aws::String& awsStr = keyObject.GetKey();
        keys.emplace_back(awsStr.c_str());
    }

    return keys;
}

void S3Wrapper::deleteKey(const std::string& bucketName,
                          const std::string& keyName)
{
    SPDLOG_DEBUG("Deleting key {}/{}", bucketName, keyName);
    Aws::S3::Model::DeleteObjectRequest request;
    request.SetBucket(Aws::String(bucketName));
    request.SetKey(Aws::String(keyName));

    auto response = client.DeleteObject(request);

    if (!response.IsSuccess()) {
        const auto& err = response.GetError();
        handleError(err);
    }
}

void S3Wrapper::addKeyBytes(const std::string& bucketName,
                            const std::string& keyName,
                            const std::vector<uint8_t>& data)
{
    const char* charPtr = reinterpret_cast<const char*>(data.data());
    addKey(bucketName, keyName, charPtr, data.size());
}

void S3Wrapper::addKeyStr(const std::string& bucketName,
                          const std::string& keyName,
                          const std::string& data)
{
    addKey(bucketName, keyName, data.c_str(), data.size());
}

std::vector<uint8_t> S3Wrapper::getKeyBytes(const std::string& bucketName,
                                            const std::string& keyName)
{
    const std::string& byteStr = getKey(bucketName, keyName);

    const std::vector<uint8_t>& bytes = faabric::util::stringToBytes(byteStr);

    return bytes;
}

std::string S3Wrapper::getKeyStr(const std::string& bucketName,
                                 const std::string& keyName)
{
    return getKey(bucketName, keyName);
}

void S3Wrapper::addKey(const std::string& bucketName,
                       const std::string& keyName,
                       const char* data,
                       size_t dataLen)
{
    SPDLOG_DEBUG("Writing {} to bucket {}", keyName, bucketName);

    Aws::S3::Model::PutObjectRequest request;
    request.SetBucket(Aws::String(bucketName));
    request.SetKey(Aws::String(keyName));

    std::shared_ptr<Aws::IOStream> dataStream =
      Aws::MakeShared<Aws::StringStream>(data);
    dataStream->write(data, dataLen);
    request.SetBody(dataStream);

    auto response = client.PutObject(request);

    if (!response.IsSuccess()) {
        const auto& err = response.GetError();
        handleError(err);
    }
}

std::string S3Wrapper::getKey(const std::string& bucketName,
                              const std::string& keyName)
{
    SPDLOG_DEBUG("Getting key {}/{}", bucketName, keyName);
    Aws::S3::Model::GetObjectRequest request;
    request.SetBucket(Aws::String(bucketName));
    request.SetKey(Aws::String(keyName));

    auto response = client.GetObject(request);

    if (!response.IsSuccess()) {
        const auto& err = response.GetError();
        handleError(err);
    }

    std::ostringstream ss;
    auto* responseStream = response.GetResultWithOwnership().GetBody().rdbuf();
    ss << responseStream;

    return ss.str();
}
}
