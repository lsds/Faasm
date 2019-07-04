#include <iostream>
#include <fstream>

#include <util/logging.h>
#include <data/data.h>
#include <emulator/emulator.h>
#include <state/State.h>

#include <faasm/matrix.h>
#include <faasm/sgd.h>
#include <faasm/counter.h>
#include <faasm/time.h>

using namespace faasm;

int main() {
    util::initLogging();
    state::getGlobalState().forceClearAll();
    const std::shared_ptr<spdlog::logger> &logger = util::getLogger();

    // Override emulator user
    setEmulatorUser("sgd");

    int nBatches = 4;
    int epochs = 30;
    SgdParams p = setUpReutersParams(nBatches, epochs);

    logger->info("Running SVM with {} threads (batch size {})", p.nBatches, p.batchSize);

    // Initialise weights to zero
    Eigen::MatrixXd weights = faasm::zeroMatrix(1, p.nWeights);
    bool fullAsync = getEnvFullAsync();
    writeMatrixToState(WEIGHTS_KEY, weights, fullAsync);

    // Clear out existing state
    faasm::zeroLosses(p);

    // Run each epoch
    std::vector<std::pair<double, double>> losses;
    double startTs = faasm::getSecondsSinceEpoch();
    for (int epoch = 0; epoch < p.nEpochs; epoch++) {
        logger->info("Epoch {} start", epoch);

        faasm::zeroErrors(p);
        faasm::zeroFinished(p);

        data::runPool(p, epoch);

        // Work out error
        double rmse = data::getRMSE(p);
        double thisTs = faasm::getSecondsSinceEpoch() - startTs;

        losses.emplace_back(std::pair<double, double>(thisTs, rmse));

        logger->info("Epoch {} end   - time {:04.2f}s - RMSE {:06.4f}", epoch, thisTs, rmse);

        // Decay learning rate (it appears hogwild doesn't actually do this even though it takes in a param
        // p.learningRate = p.learningRate * p.learningDecay;
        // faasm::writeParamsToState(PARAMS_KEY, p);
    }

    std::ofstream resultFile;
    std::string fileName = "measurement/THREADS_" + std::to_string(nBatches) + ".txt";
    resultFile.open(fileName);
    double tsZero = losses.at(0).first;
    for (auto loss : losses) {
        resultFile << loss.first - tsZero << " " << loss.second << std::endl;
    }
    resultFile.close();
}
