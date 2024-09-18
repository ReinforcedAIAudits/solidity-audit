from fastapi import FastAPI
from pydantic import BaseModel
import random

app = FastAPI()

class Numbers(BaseModel):
    a: int
    b: int

@app.post('/add')
async def add_numbers(numbers: Numbers):
    a = numbers.a
    b = numbers.b
    random_num = random.randint(1, 100)
    result = a + b + random_num
    return {"result": result, "random_number": random_num}

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=5000)
