package ve.gob.cenditel.murachi;


/**
 * Clase PresignParameters que representa el objeto que se mapea al JSON
 * que se envia a /archivos/prepararfirmapdf
 * 
 * @author aaraujo
 *
 */
public class PresignParameters {

	private String fileId;
	
	private String certificate;
	
	public String getFileId() {
		return fileId;
	}
	
	public void setFileId(String id) {
		fileId = id;
	}
	
	public String getCertificate() {
		return certificate;
	}
	
	public void setCertificate(String cert) {
		certificate = cert;
	}
}
