import os
import uvicorn

if __name__ == "__main__":
    is_production = os.environ.get("ENV", "development").lower() == "production"
    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=8000,
        reload=not is_production,
    )
