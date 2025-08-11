# Use the official Astral uv image with Python 3.13 on Alpine
FROM ghcr.io/astral-sh/uv:python3.13-alpine

# Install Node.js and npm (for npx support)
RUN apk add --no-cache curl \
    && curl -fsSL https://unofficial-builds.nodejs.org/download/release/v18.20.2/node-v18.20.2-linux-x64-musl.tar.xz -o node.tar.xz \
    && mkdir -p /usr/local/lib/nodejs \
    && tar -xJf node.tar.xz -C /usr/local/lib/nodejs \
    && ln -s /usr/local/lib/nodejs/node-v18.20.2-linux-x64-musl/bin/node /usr/local/bin/node \
    && ln -s /usr/local/lib/nodejs/node-v18.20.2-linux-x64-musl/bin/npm /usr/local/bin/npm \
    && ln -s /usr/local/lib/nodejs/node-v18.20.2-linux-x64-musl/bin/npx /usr/local/bin/npx \
    && rm node.tar.xz

# Set work directory
WORKDIR /app

RUN uv venv
RUN source .venv/bin/activate
# Copy requirements and install Python dependencies with uv
COPY requirements.txt .
RUN uv pip install -r requirements.txt

# Copy the rest of the app code
COPY . .

# Expose the port your app runs on
EXPOSE 8081

ENV PATH="/app/.venv/bin:$PATH"

# Run the FastAPI app with uvicorn
CMD ["uvicorn", "vul_mcp:app", "--host", "0.0.0.0", "--port", "8081"]