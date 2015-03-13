package ve.gob.cenditel.murachi;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.UUID;
import java.text.DateFormat;
import java.text.SimpleDateFormat;










import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.OPTIONS;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.glassfish.jersey.media.multipart.FormDataContentDisposition;
import org.glassfish.jersey.media.multipart.FormDataParam;
import org.json.JSONObject;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfDate;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignature;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfString;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;



@Path("/archivos")
public class MurachiRESTWS {

	private static final String SERVER_UPLOAD_LOCATION_FOLDER = "/tmp/"; 
	
	/**
	 * Carga un archivo pasado a través de un formulario y retorna 
	 * un json con el id del archivo en el servidor para futuras consultas
	 * 
	 * @param uploadedInputStream stream para obtener el archivo
	 * @param fileDetails datos del archivo
	 * @return
	 */
	@POST
	@Path("/cargar")
	@Consumes(MediaType.MULTIPART_FORM_DATA)
	@Produces(MediaType.APPLICATION_JSON)
	public Response uploadFile(
			@FormDataParam("upload") InputStream uploadedInputStream,
			@FormDataParam("upload") FormDataContentDisposition fileDetails) {
		
		//TODO manejar las excepciones correctamente
		if (uploadedInputStream == null) {
			System.out.println("uploadedInputStream == null");
		}
		
		if (fileDetails == null) {
			System.out.println("fileDetails == null");
		}
				
		String fileId = UUID.randomUUID().toString();
		System.out.println(fileId);
		
		saveToDisk(uploadedInputStream, fileDetails, fileId);
		
		try {
			uploadedInputStream.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("fileId", fileId);
		
		System.out.println("File saved to server location : " + SERVER_UPLOAD_LOCATION_FOLDER + fileId);
		String result = jsonObject.toString();
		
		return Response.status(200).entity(result).build();
	}
	
	
	
	/**
	 * Escribe un archivo en el sistema de archivos 
	 * @param uploadedInputStream
	 * @param fileDetails
	 * @param fileId identificador unico del archivo de acuerdo a UUIDs
	 */
	private void saveToDisk(InputStream uploadedInputStream, FormDataContentDisposition fileDetails, String fileId) {
		
		String uploadedFileLocation = SERVER_UPLOAD_LOCATION_FOLDER + /*fileDetails.getFileName()*/ fileId;
		System.out.println("uploadedFileLocation: " + uploadedFileLocation);
		
		try {
			OutputStream out = new FileOutputStream(new File(uploadedFileLocation));
			int read = 0;
			byte[] bytes = new byte[1024];
			
			out = new FileOutputStream(new File(uploadedFileLocation));
			while ((read = uploadedInputStream.read(bytes)) != -1) {
				out.write(bytes, 0, read);
				
			}
			out.flush();
			out.close();
		}
		catch(IOException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Verifica si un archivo posee firmas electronicas y retorna informacion
	 * de las mismas en un json
	 * @param idFile
	 * @return
	 */
	@GET
	@Path("/verificar/{idFile}")
	//@Produces("application/json")
	@Produces("text/plain")
	public String verifyFile(@PathParam("idFile") String idFile) {
		
		String file = SERVER_UPLOAD_LOCATION_FOLDER + idFile;
	
		//return getMimeType(file);
		
				
		File tmpFile = new File(file);
		String result = "";

		
		
		
		if (tmpFile.exists()) {
			result = "El archivo existe.";
			
			try {
				PdfReader reader = new PdfReader(file);
				AcroFields af = reader.getAcroFields();
				ArrayList<String> names = af.getSignatureNames();
				if (names.size() > 0) {
					result = "el archivo PDF posee "+ names.size() +" firma(s).\n";
					
					// sin esto explota: se debe agregar una implementacion del provider en tiempo de ejecucion
					//http://www.cs.berkeley.edu/~jonah/bc/org/bouncycastle/jce/provider/BouncyCastleProvider.html
					Security.addProvider(new BouncyCastleProvider());
					
					for (String name: names) {
						result = result +"Nombre de la firma: "+ name + "\n";
						System.out.println("Nombre de la firma: "+ name);
						
						PdfPKCS7 pk = af.verifySignature(name);
						
						Certificate[] pkc = pk.getCertificates();
						
						String tmpSignerName = pk.getSigningCertificate().getSubjectX500Principal().toString();
						
						
						result = result + "Sujeto del certificado firmante: " + tmpSignerName + "\n"; 
						//pk.getSigningCertificate().getSubjectX500Principal().getName() + "\n";
						System.out.println("Sujeto del certificado firmante: " + 
								pk.getSigningCertificate().getSubjectX500Principal().toString());
						  
						Calendar cal = pk.getSignDate();
						
						SimpleDateFormat date_format = new SimpleDateFormat("dd/MM/yyyy hh:mm:ss");
						
						//result = result + "Fecha de la firma: " + cal.toString() + "\n";
						result = result + "Fecha de la firma: " + date_format.format(cal.getTime()) + "\n";
						
						/*
						System.out.println("año: "+ cal.get(Calendar.YEAR));
						System.out.println("mes: "+ (cal.get(Calendar.MONTH) + 1));
						System.out.println("día: "+ cal.get(Calendar.DAY_OF_MONTH));
						System.out.println("hora: "+ cal.get(Calendar.HOUR));
						System.out.println("minuto: "+ cal.get(Calendar.MINUTE));
						System.out.println("segundo: "+ cal.get(Calendar.SECOND));
						*/
						//SimpleDateFormat date_format = new SimpleDateFormat("dd/MM/yyyy hh:mm:ss");
					    System.out.println(date_format.format(cal.getTime()));

					}
					
					
				}else{
					result = "el archivo PDF no posee firmas";
				}
				
				
				
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			
		}else {
			result = "El archivo NO existe.";
		}
		
		
		return result;
		
		
	}
	
	/**
	 * Ejecuta el proceso de presign o preparacion de firma de documento pdf
	 * @param presignPar
	 * @param req objeto request para crear una sesion y mantener elementos del 
	 * pdf en la misma
	 * @param resp
	 */
	@POST
	@Path("/prepararfirmapdf")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	//public Response presign(PresignParameters presignPar, @Context HttpServletRequest req) {
	public PresignHash presign(PresignParameters presignPar, @Context HttpServletRequest req) {
		

		// cadena resultado de la funcion
		String result = "";
		
		PresignHash presignHash = new PresignHash();
		
		
		// cadena con el certificado
		String certHex = presignPar.getCertificate();
		System.out.println("certificado en Hex: " + certHex);
		
		// obtener el id del archivo 
		String fileId = presignPar.getFileId();
				
		try {
			CertificateFactory factory = CertificateFactory.getInstance("X.509");
			Certificate[] chain = new Certificate[1];
			
			InputStream in = new ByteArrayInputStream(hexStringToByteArray(certHex));
			chain[0] = factory.generateCertificate(in);
			
			if (chain[0] == null) {
				System.out.println("error chain[0] == null");
			}else {
				
				System.out.println("se cargo el certificado correctamente");
				System.out.println(chain[0].toString());
			}
			
			//String pdf = SERVER_UPLOAD_LOCATION_FOLDER + "e27a6a90-f955-4191-8e54-580e316a999d";
			String pdf = SERVER_UPLOAD_LOCATION_FOLDER + fileId;
			System.out.println("archivo a firmar: " + pdf);
			
			PdfReader reader = new PdfReader(pdf);
			
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			
			//FileOutputStream baos = new FileOutputStream(pdf+"-signed.pdf");
			
			PdfStamper stamper = PdfStamper.createSignature(reader, baos, '\0');
			
			// crear la apariencia de la firma
	    	PdfSignatureAppearance sap = stamper.getSignatureAppearance();
	    	sap.setReason("Prueba de firma en dos partes");
	    	sap.setLocation("Merida, Venezuela");
	    	sap.setVisibleSignature(new Rectangle(36, 748, 144,780),1, "sig");
	    	sap.setCertificate(chain[0]);
	    	
	    	// crear la estructura de la firma
	    	PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, PdfName.ADBE_PKCS7_DETACHED);
	    	dic.setReason(sap.getReason());
	    	dic.setLocation(sap.getLocation());
	    	dic.setContact(sap.getContact());
	    	dic.setDate(new PdfDate(sap.getSignDate()));
	    	
	    	sap.setCryptoDictionary(dic);
	    	
	    	HashMap<PdfName, Integer> exc = new HashMap<PdfName, Integer> ();
	    	exc.put(PdfName.CONTENTS, new Integer(8192 * 2 + 2));
	    	sap.preClose(exc);
	    	
	    	ExternalDigest externalDigest = new ExternalDigest() {
	    		public MessageDigest getMessageDigest(String hashAlgorithm)
	    		throws GeneralSecurityException {
	    			return DigestAlgorithms.getMessageDigest(hashAlgorithm, null);
	    		}
	    	};
			
			
	    	PdfPKCS7 sgn = new PdfPKCS7(null, chain, "SHA256", null, externalDigest, false);
	    	
	    	InputStream data = sap.getRangeStream();
	    	
	    	byte hash[] = DigestAlgorithms.digest(data, externalDigest.getMessageDigest("SHA256"));
	    	
	    	Calendar cal = Calendar.getInstance();
	    	byte sh[] = sgn.getAuthenticatedAttributeBytes(hash, cal, null, null, CryptoStandard.CMS);
	    	
	    	sh = DigestAlgorithms.digest(new ByteArrayInputStream(sh), externalDigest.getMessageDigest("SHA256"));
	    	
	    	System.out.println("sh length: "+ sh.length);
	    	    	
	    	String hashToSign = byteArrayToHexString(sh);
	    	System.out.println("***************************************************************");
	    	System.out.println("HASH EN HEXADECIMAL:");
	    	System.out.println(hashToSign);
	    	System.out.println("length: " +hashToSign.length());	
	    	System.out.println("***************************************************************");
			
	    	DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
			Date date = new Date();
			System.out.println(dateFormat.format(date));
			//String d = dateFormat.format(date);
			
			
			// almacenar los objetos necesarios para realizar el postsign en una sesion
			HttpSession session = req.getSession(true);
			session.setAttribute("hashToSign", hashToSign);
			
			session.setAttribute("stamper", stamper);
			session.setAttribute("sgn", sgn);
			session.setAttribute("hash", hash);
			session.setAttribute("cal", cal);
			session.setAttribute("sap", sap);
			session.setAttribute("baos", baos);
			session.setAttribute("fileId", fileId);
			
			// creacion del json
			JSONObject jsonHash = new JSONObject();
			jsonHash.put("hashToSign", hashToSign);
			
			result = jsonHash.toString();
			
			presignHash.setHash(hashToSign);
				
			
		} catch (CertificateException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (DocumentException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		//return Response.status(200).entity(result).build();
		return presignHash;
			
	}
	
	
	/**
	 * Ejecuta el proceso de postsign o completacion de firma de documento pdf
	 * @param postsignPar
	 * @param req objeto request para crear una sesion y mantener elementos del 
	 * pdf en la misma
	 * @param resp
	 * @throws IOException 
	 */
	@POST
	@Path("/completarfirmapdf")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response postsign(PostsignParameters postsignPar, @Context HttpServletRequest req) throws IOException {
		
		
		// cadena resultado de la funcion
		String result = "";
				
		// cadena con la firma
		String signature = postsignPar.getSignature();
		System.out.println("firma en Hex: " + signature);
		
		HttpSession session = req.getSession(false);
		
		String fileId = (String) session.getAttribute("fileId");
		System.out.println("fileId: " + fileId);
		
		PdfStamper stamper = (PdfStamper) session.getAttribute("stamper");
		
		PdfPKCS7 sgn = (PdfPKCS7) session.getAttribute("sgn");
		
		byte[] hash = (byte[]) session.getAttribute("hash");
		
		Calendar cal = (Calendar) session.getAttribute("cal");
		
		PdfSignatureAppearance sap = (PdfSignatureAppearance) session.getAttribute("sap");
		
		ByteArrayOutputStream os = (ByteArrayOutputStream) session.getAttribute("baos");
		
		if (sgn == null) {
			System.out.println("sgn == null");
		}
		if (hash == null) {
			System.out.println("hash == null");
		}
		if (cal == null) {
			System.out.println("cal == null");
		}
		if (sap == null) {
			System.out.println("sap == null");
		}
		if (os == null) {
			System.out.println("os == null");
		}
		
		
		
		// convertir signature en bytes		
		byte[] signatureInBytes = hexStringToByteArray(signature);
				
		// completar el proceso de firma
		sgn.setExternalDigest(signatureInBytes, null, "RSA");
		byte[] encodeSig = sgn.getEncodedPKCS7(hash, cal, null, null, null, CryptoStandard.CMS);
		byte[] paddedSig = new byte[8192];
		System.arraycopy(encodeSig, 0, paddedSig, 0, encodeSig.length);
		PdfDictionary dic2 = new PdfDictionary();
		dic2.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));
		try {
			sap.close(dic2);
			
			stamper.close();
			System.out.println("stamper.close");
			
		}catch(DocumentException e) {
			
			System.out.println("throw new IOException");
			throw new IOException(e);
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println("IOException e");
			e.printStackTrace();
			
		}
		
		String signedPdf = SERVER_UPLOAD_LOCATION_FOLDER + fileId + "-signed.pdf";
		
		FileOutputStream signedFile = new FileOutputStream(signedPdf);
		
		os.writeTo(signedFile);
		os.flush();
		
		
		
		// en este punto el archivo pdf debe estar disponible en la ruta
		// SERVER_UPLOAD_LOCATION_FOLDER + fileId;
		
		// llamar a una funcion que permita descargar el archivo
		
		result = "Archivo firmado correctamente";
		System.out.println("Archivo firmado correctamente");
		
		return Response.status(200).entity(result).build();
	}
	
	
	
	
	/**
	 * Prueba de ejecucion de programa desde consola. Incompleta
	 * @return
	 * @throws InterruptedException
	 */
	@GET
	@Path("/ejecutar")
	@Produces("text/plain")
	public String executeProcess() throws InterruptedException {
		
		
		String line = "";
		OutputStream stdin = null;
		InputStream stderr = null;
		InputStream stdout = null;
		
		try {
			System.out.print("...a crear el proceso");
			Process process = Runtime.getRuntime().exec("/usr/java/jdk1.7.0_21/bin/java -jar /home/aaraujo/desarrollo/2015/servicioVerificacion/testsigningpdf/holamundopdf.jar /tmp/589750.pdf /tmp/simonDiaz.pem /tmp/firmadoconsola.pdf");
			//Process process = Runtime.getRuntime().exec("ls -l");
			stdin = process.getOutputStream();
			stderr = process.getErrorStream();
			stdout = process.getInputStream();
			
			InputStreamReader isr = new InputStreamReader(stdout);
			BufferedReader buff = new BufferedReader (isr);

			
			while((line = buff.readLine()) != null)
				System.out.print(line+"\n");
			int exitValue = process.waitFor();
			if (exitValue != 0) {
			    System.out.println("Abnormal process termination");
			}	
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.print("...saliendo");
		return line;
	}
	
	
	
	
	
	/**
	 * 
	 * @param certHex
	 * @param httpHeaders
	 * @param req
	 * @param resp
	 */
	@POST
	@Path("/presignOld")
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public void presignOld(
			@FormParam("certHexInForm") String certHex,
			@Context HttpHeaders httpHeaders,
			@Context HttpServletRequest req,
			@Context HttpServletResponse resp) {
		

		String host = httpHeaders.getRequestHeader("host").get(0);
		
		String agent = httpHeaders.getRequestHeader("user-agent").get(0);
		String salida = "User agent :"+ agent +" from host : "+host;
		System.out.println(host);
		System.out.println(agent);
		System.out.println(salida);
		
		System.out.println("certificado en Hex: " + certHex);
		
		try {
			CertificateFactory factory = CertificateFactory.getInstance("X.509");
			Certificate[] chain = new Certificate[1];
			
			InputStream in = new ByteArrayInputStream(hexStringToByteArray(certHex));
			chain[0] = factory.generateCertificate(in);
			
			if (chain[0] == null) {
				System.out.println("error chain[0] == null");
			}else {
				
				System.out.println("se cargo el certificado correctamente");
				System.out.println(chain[0].toString());
			}
			
			String pdf = SERVER_UPLOAD_LOCATION_FOLDER + "e27a6a90-f955-4191-8e54-580e316a999d";
			
			PdfReader reader = new PdfReader(pdf);
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			PdfStamper stamper = PdfStamper.createSignature(reader, baos, '\0');
			
			// crear la apariencia de la firma
	    	PdfSignatureAppearance sap = stamper.getSignatureAppearance();
	    	sap.setReason("Prueba de firma en dos partes");
	    	sap.setLocation("Merida, Venezuela");
	    	sap.setVisibleSignature(new Rectangle(36, 748, 144,780),1, "sig");
	    	sap.setCertificate(chain[0]);
	    	
	    	// crear la estructura de la firma
	    	PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, PdfName.ADBE_PKCS7_DETACHED);
	    	dic.setReason(sap.getReason());
	    	dic.setLocation(sap.getLocation());
	    	dic.setContact(sap.getContact());
	    	dic.setDate(new PdfDate(sap.getSignDate()));
	    	
	    	sap.setCryptoDictionary(dic);
	    	
	    	HashMap<PdfName, Integer> exc = new HashMap<PdfName, Integer> ();
	    	exc.put(PdfName.CONTENTS, new Integer(8192 * 2 + 2));
	    	sap.preClose(exc);
	    	
	    	ExternalDigest externalDigest = new ExternalDigest() {
	    		public MessageDigest getMessageDigest(String hashAlgorithm)
	    		throws GeneralSecurityException {
	    			return DigestAlgorithms.getMessageDigest(hashAlgorithm, null);
	    		}
	    	};
			
			
	    	PdfPKCS7 sgn = new PdfPKCS7(null, chain, "SHA256", null, externalDigest, false);
	    	
	    	InputStream data = sap.getRangeStream();
	    	
	    	byte hash[] = DigestAlgorithms.digest(data, externalDigest.getMessageDigest("SHA256"));
	    	
	    	Calendar cal = Calendar.getInstance();
	    	byte sh[] = sgn.getAuthenticatedAttributeBytes(hash, cal, null, null, CryptoStandard.CMS);
	    	
	    	sh = DigestAlgorithms.digest(new ByteArrayInputStream(sh), externalDigest.getMessageDigest("SHA256"));
	    	
	    	System.out.println("sh length: "+ sh.length);
	    	    	
	    	String hashToSign = byteArrayToHexString(sh);
	    	System.out.println("***************************************************************");
	    	System.out.println("HASH EN HEXADECIMAL:");
	    	System.out.println(hashToSign);
	    	System.out.println("length: " +hashToSign.length());	
	    	System.out.println("***************************************************************");
			
	    	DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
			Date date = new Date();
			System.out.println(dateFormat.format(date));
			String d = dateFormat.format(date);
			
			
			// almacenar los objetos necesarios para realizar el postsign en una sesion
			HttpSession session = req.getSession(true);
			session.setAttribute("hashToSign", hashToSign);
			
			session.setAttribute("sgn", sgn);
			session.setAttribute("hash", hash);
			session.setAttribute("cal", cal);
			session.setAttribute("sap", sap);
			session.setAttribute("baos", baos);
			
		
			
			resp.sendRedirect("http://localhost/murachi2.html");
			
			
		} catch (CertificateException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (DocumentException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	
	}
	
	
	@POST
	@Path("/postsign")
	public String postsignOld(@Context HttpServletRequest req,
			@Context HttpServletResponse resp) {
		
		System.out.println("...postsign()...");
		
		HttpSession session = req.getSession(false);
		Object att = session.getAttribute("hashToSign");
				
	
		String output = "atributo leido de la sesion: " + att.toString();
		
		
		return output;
		//return Response.status(200).entity(output).build();
	}
	
	
	@GET
	@Path("/retornajson")
	@Produces(MediaType.APPLICATION_JSON)
	public PresignHash retornajson(@Context HttpServletRequest req) {
		
		
		
		PresignHash h = new PresignHash();
		h.setHash("ESTO SERIA UN HASH");
		
		System.out.println("...retornajson..."+ h.getHash());
		
		return h;
		
	}
	
	@POST
	@Path("/enviarjson")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public PresignHash recibejson( PresignParameters par) {
		
		String fileId = par.getFileId();
		System.out.println("...fileId recibido..."+ fileId);
		
		String cert = par.getCertificate();
		System.out.println("...certificate recibido..."+ cert);
		
		PresignHash h = new PresignHash();
		h.setHash("DEBES FIRMAR ESTO");
		
		System.out.println("...recibejson..."+ h.getHash());
		
		return h;
		
	}
	
	
	
	
	/**
	 * Retorna el mimeType del archivo pasado como argumento
	 * @param absolutFilePath ruta absoluta del archivo
	 * @return mimeType del archivo pasado como argumento
	 */
	public String getMimeType(String absolutFilePath) {
				
		String result = "";		
		java.nio.file.Path source = Paths.get(absolutFilePath);
		try {
			result = Files.probeContentType(source);			
			System.out.println(result);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}		
		return result;		 
	}
	
	/**
	 * Convierte una cadena Hexadecimal en un arreglo de bytes
	 * @param s cadena hexadecimal
	 * @return arreglo de bytes resultantes de la conversion de la cadena hexadecimal
	 */
	public static byte[] hexStringToByteArray(String s) {
	    byte[] b = new byte[s.length() / 2];
	    for (int i = 0; i < b.length; i++) {
	      int index = i * 2;
	      int v = Integer.parseInt(s.substring(index, index + 2), 16);
	      b[i] = (byte) v;
	    }
	    return b;
	  }
	
	/**
	   * Converts a byte array into a hex string.
	   * @param byteArray the byte array source
	   * @return a hex string representing the byte array
	   */
	  public static String byteArrayToHexString(final byte[] byteArray) {
	      if (byteArray == null) {
	          return "";
	      }
	      return byteArrayToHexString(byteArray, 0, byteArray.length);
	  }
	  
	  public static String byteArrayToHexString(final byte[] byteArray, int startPos, int length) {
	      if (byteArray == null) {
	          return "";
	      }
	      if(byteArray.length < startPos+length){
	          throw new IllegalArgumentException("startPos("+startPos+")+length("+length+") > byteArray.length("+byteArray.length+")");
	      }
//	      int readBytes = byteArray.length;
	      StringBuilder hexData = new StringBuilder();
	      int onebyte;
	      for (int i = 0; i < length; i++) {
	          onebyte = ((0x000000ff & byteArray[startPos+i]) | 0xffffff00);
	          hexData.append(Integer.toHexString(onebyte).substring(6));
	      }
	      return hexData.toString();
	  }
	
}
