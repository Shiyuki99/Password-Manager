# Makefile for Password Manager

CXX = g++
CXXFLAGS = -std=c++23 -Wall -Wextra
LIBS = -lsodium -lstdc++fs
SOURCES = src/main.cpp
TARGET = password_manager

# Test configuration
TEST_SOURCES = tests/test_encrypt_decrypt.cpp
TEST_TARGET = test_runner
TEST_LIBS = -lgtest -lgtest_main -lpthread -lsodium

# Default target
.PHONY: all clean run test help

all: $(TARGET)

# Build the application
$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCES) $(LIBS)

# Build and run tests
test: $(TEST_TARGET)
	./$(TEST_TARGET)

$(TEST_TARGET): $(TEST_SOURCES)
	$(CXX) $(CXXFLAGS) -I src -o $(TEST_TARGET) $(TEST_SOURCES) $(TEST_LIBS)

# Clean build artifacts
clean:
	rm -f $(TARGET) $(TEST_TARGET)

# Run the application
run: $(TARGET)
	./$(TARGET)

# Help target
help:
	@echo "Available targets:"
	@echo "  all   - Build the application"
	@echo "  clean - Remove build artifacts"
	@echo "  run   - Build and run the application"
	@echo "  test  - Build and run tests"
	@echo "  help  - Show this help"