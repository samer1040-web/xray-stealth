FROM python:3.10-slim
WORKDIR /app
COPY socks_gateway.py proxies.txt ./
EXPOSE 8080
ENV SOCKS_USER=admin
ENV SOCKS_PASS=123456
CMD ["python", "socks_gateway.py", "--host", "0.0.0.0", "--port", "8080"]