from fastapi import FastAPI

app = FastAPI(title="Dashboard", description="This is an example app.", version="0.0.1")


@app.on_event("startup")
async def startup():
    pass


@app.on_event("shutdown")
async def shutdown():
    pass
