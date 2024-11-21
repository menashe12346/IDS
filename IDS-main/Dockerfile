# Use a slim Python image
FROM python:3.9-slim

# Install tcpreplay and other necessary tools
RUN apt-get update && apt-get install -y \
    tcpreplay \
    tcpdump \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies (e.g., Scapy)
RUN pip install scapy

# Set the working directory inside the container
WORKDIR /app

# Copy your project files into the container
COPY . /app

# Set the entry point to run your packet analyzer script
CMD ["python", "main.py"]
