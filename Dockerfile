FROM ghcr.io/astral-sh/uv:python3.10-bookworm-slim

# Set working directory
WORKDIR /app

# Install system dependencies (nmap and curl)
RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN uv venv

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies with uv
RUN uv pip install -r requirements.txt

# Copy application code
COPY . .

# Expose port
EXPOSE 8000

# Set environment variables
ENV PORT=8000
ENV PYTHONUNBUFFERED=1
ENV PATH="/app/.venv/bin:$PATH"

# Run the application in streamable mode (HTTP)
CMD ["uv", "run", "vul_mcp.py", "streamable"]