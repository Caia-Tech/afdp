#!/bin/bash

# Generate Python protobuf files from the proto definition

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROTO_DIR="../../proto"
PROTO_FILE="${PROTO_DIR}/notary.proto"

echo "🔧 Generating Python protobuf files..."

# Check if proto file exists
if [ ! -f "$PROTO_FILE" ]; then
    echo "❌ Proto file not found: $PROTO_FILE"
    exit 1
fi

# Check if protoc is available
if ! command -v python -m grpc_tools.protoc &> /dev/null; then
    echo "❌ grpc_tools not found. Installing requirements..."
    pip install -r requirements.txt
fi

# Generate Python files
echo "📦 Generating protobuf Python files..."
python -m grpc_tools.protoc \
    -I"$PROTO_DIR" \
    -I"$(python -c "import grpc_tools; print(grpc_tools.__path__[0])")/_proto" \
    --python_out="$SCRIPT_DIR" \
    --grpc_python_out="$SCRIPT_DIR" \
    "$PROTO_FILE"

# Check if files were generated
if [ -f "notary_pb2.py" ] && [ -f "notary_pb2_grpc.py" ]; then
    echo "✅ Successfully generated:"
    echo "   - notary_pb2.py (protobuf messages)"
    echo "   - notary_pb2_grpc.py (gRPC service stubs)"
else
    echo "❌ Failed to generate protobuf files"
    exit 1
fi

echo "🎉 Protobuf generation complete!"