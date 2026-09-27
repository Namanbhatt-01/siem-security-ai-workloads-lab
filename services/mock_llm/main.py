import asyncio
import logging
from typing import Dict, Any, List
from fastapi import FastAPI, Request, Response
import uvicorn

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("mock_llm_service")

# App 1: LLM Inference API (Port 8000)
llm_app = FastAPI(title="Mock LLM Inference Gateway", version="1.0.0")

@llm_app.get("/health")
async def health():
    return {"status": "ok", "service": "llm_inference_gateway"}

@llm_app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    body = await request.json()
    client_ip = request.client.host if request.client else "unknown"
    messages = body.get("messages", [])
    model = body.get("model", "llama-3-70b-instruct")
    
    prompt_text = " ".join([m.get("content", "") for m in messages])
    logger.info(f"[LLM-INGRESS] client={client_ip} model={model} prompt_len={len(prompt_text)} preview='{prompt_text[:80]}'")

    # Mock response
    response_content = f"Model response from {model}: Query received successfully."
    return {
        "id": "chatcmpl-mock-12345",
        "object": "chat.completion",
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": response_content
                },
                "finish_reason": "stop"
            }
        ],
        "usage": {
            "prompt_tokens": len(prompt_text.split()),
            "completion_tokens": len(response_content.split()),
            "total_tokens": len(prompt_text.split()) + len(response_content.split())
        }
    }

@llm_app.post("/v1/embeddings")
async def embeddings(request: Request):
    body = await request.json()
    input_text = body.get("input", "")
    logger.info(f"[EMBEDDINGS-INGRESS] input_len={len(input_text)}")
    return {
        "object": "list",
        "data": [{"object": "embedding", "index": 0, "embedding": [0.01] * 1536}],
        "model": "text-embedding-3-small"
    }

# App 2: Vector DB Service (Port 6333 - Qdrant/Milvus Mock)
vector_app = FastAPI(title="Mock Vector DB", version="1.0.0")

@vector_app.get("/health")
async def vector_health():
    return {"status": "ok", "service": "mock_vector_db"}

@vector_app.get("/collections/{collection_name}/dump")
async def vector_dump(collection_name: str, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    logger.warning(f"[VECTOR-DB-ACCESS] Unauthorized bulk dump attempt on collection={collection_name} from client={client_ip}")
    return {
        "collection": collection_name,
        "total_records": 10000,
        "status": "exfiltrated_chunk_mock",
        "payload_size_kb": 1024
    }

@vector_app.post("/collections/{collection_name}/points/search")
async def vector_search(collection_name: str, request: Request):
    body = await request.json()
    return {"result": [{"id": 1, "score": 0.99, "payload": {"meta": "mock_context"}}]}

async def run_servers():
    config_llm = uvicorn.Config(llm_app, host="0.0.0.0", port=8000, log_level="info")
    config_vector = uvicorn.Config(vector_app, host="0.0.0.0", port=6333, log_level="info")

    server_llm = uvicorn.Server(config_llm)
    server_vector = uvicorn.Server(config_vector)

    await asyncio.gather(
        server_llm.serve(),
        server_vector.serve()
    )

if __name__ == "__main__":
    asyncio.run(run_servers())
