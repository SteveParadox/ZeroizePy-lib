# Use official Python image (Debian-based Linux)
FROM python:3.12-slim

# Install OS-level tools (optional: e.g., gcc for compiled dependencies)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create work directory
WORKDIR /app

# Copy project files (adjust if your project structure is different)
COPY . /app

# Install project dependencies
# If you have a requirements.txt:
# RUN pip install -r requirements.txt
# Otherwise install package in editable/development mode
RUN pip install -e .

# Install test dependencies
RUN pip install pytest pytest-cov hypothesis cryptography

# Command to run tests automatically when container starts
CMD ["pytest", "-q"]
