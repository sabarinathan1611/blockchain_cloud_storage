"""main.py"""
from app import create_app


app = create_app(mode='production')



if __name__ == '__main__':
    app.run(host='0.0.0.0',port=8080,debug=True)