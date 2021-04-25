#include "FileserverFileLoader.h"

#include <cpprest/astreambuf.h>
#include <cpprest/containerstream.h>
#include <faabric/util/bytes.h>
#include <faabric/util/config.h>
#include <faabric/util/files.h>
#include <faabric/util/func.h>
#include <faabric/util/logging.h>

#include <boost/filesystem.hpp>
#include <cpprest/filestream.h>
#include <cpprest/http_client.h>
#include <cpprest/json.h>
#include <cpprest/uri.h>
#include <iostream>

using namespace utility;
using namespace web;
using namespace web::http;
using namespace web::http::client;
using namespace concurrency::streams;

namespace storage {

FileserverFileLoader::FileserverFileLoader(bool useFilesystemCacheIn)
  : useFilesystemCache(useFilesystemCacheIn)
{}

std::string FileserverFileLoader::getFileserverUrl()
{
    return faabric::util::getSystemConfig().fileserverUrl;
}

std::vector<uint8_t> FileserverFileLoader::doLoad(
  const std::string& urlPath,
  const std::string& headerPath,
  const std::string& storagePath)
{
    auto logger = faabric::util::getLogger();

    // Shortcut if already exists
    if (useFilesystemCache && boost::filesystem::exists(storagePath)) {
        if (boost::filesystem::is_directory(storagePath)) {
            throw SharedFileIsDirectoryException(storagePath);
        } else {
            logger->debug("Loading from filesystem at {}", storagePath);
            return faabric::util::readFileToBytes(storagePath);
        }
    }

    auto& conf = faabric::util::getSystemConfig();
    std::string host = conf.fileserverUrl;

    logger->debug("Creating client at {}", host);
    http_client client(U(host.c_str()));

    // Build the request
    uri_builder builder;
    builder.set_path(urlPath, false);
    http_request request(methods::GET);
    request.set_request_uri(builder.to_uri());

    // Add header if necessary
    if (!headerPath.empty()) {
        request.headers().add(FILE_PATH_HEADER, headerPath);
    }

    std::vector<uint8_t> bytesData;
    client.request(request)
      .then([&logger](http_response response) {
          if (response.status_code() != 200) {
              logger->error("GET request for file failed: {}",
                            response.status_code());
              throw std::runtime_error("File GET request failed");
          }

          return response.extract_vector();
      })
      .then([&](std::vector<uint8_t> responseData) {
          size_t nBytes = responseData.size();

          // Check response data
          if (nBytes == 0) {
              std::string errMsg =
                "Empty response for file at " + host + "/" + urlPath;
              logger->error(errMsg);
              throw faabric::util::InvalidFunctionException(errMsg);
          }

          // Check whether it's a directory
          // Note - we don't want to convert every file response to a string, so
          // check the length first
          std::string isDirResponse = IS_DIR_RESPONSE;
          if (nBytes == isDirResponse.size()) {
              std::string actualResp =
                faabric::util::bytesToString(responseData);
              if (actualResp == IS_DIR_RESPONSE) {
                  throw SharedFileIsDirectoryException(headerPath);
              }
          }

          // Write bytes to file
          faabric::util::writeBytesToFile(storagePath, responseData);

          // Copy out the data
          // TODO avoid this copy?
          bytesData = responseData;
      })
      .wait();

    return bytesData;
}

std::vector<uint8_t> FileserverFileLoader::loadFunctionWasm(
  const faabric::Message& msg)
{
    std::string urlPath = fmt::format("f/{}/{}", msg.user(), msg.function());
    std::string filePath = faabric::util::getFunctionFile(msg);
    return doLoad(urlPath, "", filePath);
}

std::vector<uint8_t> FileserverFileLoader::loadFunctionObjectFile(
  const faabric::Message& msg)
{
    std::string urlPath = fmt::format("fo/{}/{}", msg.user(), msg.function());
    std::string objectFilePath = faabric::util::getFunctionObjectFile(msg);
    return doLoad(urlPath, "", objectFilePath);
}

std::vector<uint8_t> FileserverFileLoader::loadSharedObjectObjectFile(
  const std::string& path)
{
    std::string urlPath = "sobjobj";
    std::string objFilePath = faabric::util::getSharedObjectObjectFile(path);
    return doLoad(urlPath, path, objFilePath);
}

std::vector<uint8_t> FileserverFileLoader::loadSharedObjectWasm(
  const std::string& path)
{
    std::string urlPath = "sobjwasm";
    return doLoad(urlPath, path, path);
}

std::vector<uint8_t> FileserverFileLoader::loadSharedFile(
  const std::string& path)
{
    std::string urlPath = "file";
    const std::string fullPath = faabric::util::getSharedFileFile(path);
    return doLoad(urlPath, path, fullPath);
}

void FileserverFileLoader::flushFunctionFiles()
{
    // Note that because we're loading files from a file server, we can safely
    // delete the function and object files on this host as they are not the
    // master copies.
    faabric::util::SystemConfig& conf = faabric::util::getSystemConfig();

    // Nuke the function directory
    boost::filesystem::remove_all(conf.functionDir);

    // Nuke the machine code directory
    boost::filesystem::remove_all(conf.objectFileDir);
}
}
