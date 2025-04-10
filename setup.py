from setuptools import setup, find_packages

setup(
    name="crypto-tools",
    version="1.0.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'flask==2.0.1',
        'flask-swagger-ui==4.11.1',
        'Flask-SQLAlchemy==2.5.1',
        'Flask-Limiter==2.4.0',
        'Flask-CORS==3.0.10',
        'pydantic==1.8.2',
        'python-dotenv==0.19.0',
        'cryptography==3.4.7',
        'pycryptodome==3.10.1',
        'gmssl==3.2.1',
        'ecdsa==0.17.0',
        'werkzeug==2.0.1',
        'jinja2==3.0.1',
        'itsdangerous==2.0.1',
        'click==8.0.1'
    ],
) 