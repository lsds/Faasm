#ifndef FAASM_COUNTER_H
#define FAASM_COUNTER_H

namespace faasm {
    void initCounter(const char *counterKey);

    int getCounter(const char *counterKey);

    void incrementCounter(const char *counterKey);

    int incrementCounter(const char *counterKey, int increment, bool globalLock);

    class AtomicInt {
    public:
        AtomicInt();

        int operator+=(int other);

        int get();
    private:
        std::string stateKey;
        int value;
    };
}

#endif
