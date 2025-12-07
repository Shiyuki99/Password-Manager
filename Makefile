# Makefile for Password Manager

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra
LIBS = -lsodium -lstdc++fs
SOURCES = src/main.cpp
TARGET = password_manager

# Default target
.PHONY: all clean run

all: $(TARGET)

# Build the application
$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCES) $(LIBS)

# Clean build artifacts
clean:
	rm -f $(TARGET)

# Run the application
run: $(TARGET)
	./$(TARGET)

# Help target
help:
	@echo "Available targets:"
	@echo "  all  - Build the application"
	@echo "  clean - Remove build artifacts"
	@echo "  run  - Build and run the application"
	@echo "  help - Show this help"