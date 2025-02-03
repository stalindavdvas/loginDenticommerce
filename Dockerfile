# Usar una imagen base de Python 3.9
FROM python:3.9-slim

# Establecer el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copiar los archivos necesarios al contenedor
COPY . .

# Instalar las dependencias del proyecto
RUN pip install --no-cache-dir -r requirements.txt

# Exponer el puerto en el que corre la aplicación Flask
EXPOSE 5000

# Comando para ejecutar la aplicación
CMD ["python", "auth.py"]