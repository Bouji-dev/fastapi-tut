from fastapi import FastAPI, status, Response
from enum import Enum
from typing import Optional


app = FastAPI()

class TypeBlogs(str, Enum):
    mesal1 = 'mesal1'
    mesal2 = 'mesal2'
    mesal3 = 'mesal3'

@app.get('/blog/{id}/{comment_id}')
def get_comment(id:int, coment_id:int, valid:bool=True, username:Optional[str]=None):
    return{'message': f'blog id {id}, comment id {coment_id}, {valid=}, {username=}'}

@app.get('/blog/all', status_code=status.HTTP_200_OK)
def get_blogs(page:Optional[int]=None, page_size:str='test'):
    return {'message': f'{page=} -- {page_size=}'}

@app.get('/blog/type/{type}')
def get_type_blog(type:TypeBlogs):
    return {'message': f'blog type is {type}'}

@app.get('/')
def hello():
    return 'Hello Ehsan!'

# @app.get('/blog/all')
# def get_blogs():
#     return {'message': f'all blogs'}

@app.get('/blog/{id}', status_code=status.HTTP_200_OK)
def get_blog(id:int, response:Response):
    if id > 5:
        response.status_code = status.HTTP_404_NOT_FOUND
        return {'Error': f'blog {id} Not found!'}
    return {'message': f'Blogs{id}'}