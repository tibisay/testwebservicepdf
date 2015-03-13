# testwebservicepdf
Prueba de concepto de servicio web de verificación de archivos PDF y BDOC firmados electrónicamente.

Este es un EXPERIMENTO para desarrollar un servicio web REST utilizando JAX-RS con Jersey, Tomcat y Maven.

El servicio web tiene los siguientes recursos:

* `/cargar`: para cargar un archivo al servidor y mantenerlo en un espacio temporal

* `/verificar/{idFile}`: para verificar si un archivo con el identificador está firmado. En caso de estarlo muestra información de las firmas.

* `/prepararfirmapdf`: para obtener el hash del archivo pdf que se desea firmar.

* `/completarfirmapdf`: para completar la firma del archivo pdf.

Para firmar el hash del lado del cliente se utiliza el plugin de navegador [browser-token-signing](https://github.com/open-eid/browser-token-signing) y la interfaz JavaScript para firmar con token criptográfico [js-token-siging](https://github.com/open-eid/js-token-signing) del proyecto [open-eid](https://github.com/open-eid) de Estonia.

Como esto es un experimento, el código no está optimizado y seguro que existen detalles y/o errores que se deben corregir. 

