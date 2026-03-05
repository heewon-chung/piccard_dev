#include <gtest/gtest.h>

#include <iostream>
#include <string>

class PropertyPrinter : public testing::EmptyTestEventListener {
public:
    void OnTestEnd(const testing::TestInfo& test_info) override {
        const auto* result = test_info.result();
        int count = result->test_property_count();
        if (count == 0) return;

        for (int i = 0; i < count; i++) {
            const auto& prop = result->GetTestProperty(i);
            std::string key = prop.key();
            std::string val = prop.value();

            if (key.rfind("input", 0) == 0 || key.rfind("expected", 0) == 0 ||
                key.rfind("formula", 0) == 0) {
                std::cout << "    IN  " << key << ": " << val << "\n";
            } else if (key.rfind("output", 0) == 0) {
                std::cout << "    OUT " << key << ": " << val << "\n";
            }
        }
    }
};

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);

    auto& listeners = testing::UnitTest::GetInstance()->listeners();
    listeners.Append(new PropertyPrinter());

    return RUN_ALL_TESTS();
}
