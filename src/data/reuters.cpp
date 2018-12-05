#include "data/data.h"

#include <string>
#include <iostream>
#include <boost/filesystem.hpp>
#include <util/util.h>

#include <faasm/matrix.h>


using namespace boost::filesystem;

void parseReutersData(const path &dir) {
    std::string targetCategory = "CCAT";
    path outputDir("/home/scs17/faasm/reuters");
    path downloadDir("/home/scs17/faasm/rcv1rcv2aminigoutte");

    int rowCount = 18758;
    int colCount = 21531;

    path enFile = downloadDir;
    enFile.append("EN");
    enFile.append("Index_EN-EN");

    std::cout << "Reading from " << enFile << std::endl;

    std::ifstream input(enFile.c_str());

    std::string line;

    std::vector<char> categories;
    std::vector<Eigen::Triplet<double>> triplets;

    int count = 0;
    int maxCol = 0;
    while (getline(input, line)) {
        // Split up the line
        const std::vector<std::string> lineTokens = util::tokeniseString(line, ' ');
        std::string cat = lineTokens[0];

        if(cat == targetCategory) {
            categories.push_back(1);
        } else {
            categories.push_back(-1);
        }

        for (int i = 1; i < lineTokens.size(); i++) {
            // Ignore empty token
            std::basic_string<char> thisToken = lineTokens[i];
            if (util::isAllWhitespace(thisToken)) {
                continue;
            }

            // Split up index:value part
            const std::vector<std::string> valueTokens = util::tokeniseString(thisToken, ':');
            int col = std::stoi(valueTokens[0]);
            double weight = std::stof(valueTokens[1]);

            // Add to matrix.
            // NOTE: the file is 1-based. With triplets, eigen is zero-based (although when
            // indexing an array it's 1-based)
            triplets.emplace_back(Eigen::Triplet<double>(count, col - 1, weight));

            maxCol = std::max(maxCol, col);
        };

        // Move onto next row
        count++;
    }

    // Close off the file
    input.close();

    // Build a sparse matrix
    Eigen::SparseMatrix<double> mat(rowCount, colCount);
    mat.setFromTriplets(triplets.begin(), triplets.end());

    // Write matrix to files
    data::SparseMatrixFileSerialiser s(mat);
    s.writeToFile("/tmp/reuters_out/");
    
    // Write categories to files
    long nCatBytes = categories.size() * sizeof(char);
    auto catPtr = reinterpret_cast<uint8_t *>(categories.data());

    path catFile = dir;
    catFile.append("cat");

    printf("Writing %li bytes to %s\n", nCatBytes, catFile.c_str());
    util::writeBytesToFile(catFile.string(), std::vector<uint8_t>(catPtr, catPtr + nCatBytes));
}

int main() {
    path dir("/tmp/reuters_out");
    if(exists(dir)) {
        remove_all(dir);
    }

    parseReutersData(dir);

    return 0;
}
