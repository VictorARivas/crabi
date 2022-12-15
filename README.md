# crabi
Una vez clonado el repositorio: Ejecutar el comando "go mod download" para descargar todas las dependencias necesarias

1- Para levantar el API: Ejecutar el comando "go run main.go" desde la raiz del proyecto

2- Para levantar la base de datos: Desde la carpeta database ejecutar el comando "docker build . -t crabi-test" e inmediatamente después "docker run -p 54321:5432 crabi-test"

El API cuenta con 3 endpoints:

- http://localhost:5050/signup para el registro de usuario

- http://localhost:5050/login para la autenticación

- http://localhost:5050/me para mostrar la información del usuario ya loggeado
