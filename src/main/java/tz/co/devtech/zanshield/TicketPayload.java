package tz.co.devtech.zanshield;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * The JSON payload carried inside a ticket. The same shape is used for both your outbound
 * ticket and ZanShield's signed acknowledgement — fields that don't apply to a given direction
 * are simply null and omitted from the wire JSON. See Integration Guide §3.1.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TicketPayload {
    private String systemCode;
    private String institutionCode;
    private String userId;
    private String email;
    /** Optional — lets the portal greet the user by name. */
    private String fullName;
    /** Optional — needed for the user to choose SMS codes; also shown to your institution admin. */
    private String mobile;
    private String authenticationMethod;
    private String dateTime;
    private Boolean isAuthenticated;
    private String authenticationMethods;
    private String txnID;
    private Integer responseCode;
    private String message;

    public TicketPayload() {}

    public static Builder builder() {
        return new Builder();
    }

    public String getSystemCode() { return systemCode; }
    public void setSystemCode(String systemCode) { this.systemCode = systemCode; }

    public String getInstitutionCode() { return institutionCode; }
    public void setInstitutionCode(String institutionCode) { this.institutionCode = institutionCode; }

    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getFullName() { return fullName; }
    public void setFullName(String fullName) { this.fullName = fullName; }

    public String getMobile() { return mobile; }
    public void setMobile(String mobile) { this.mobile = mobile; }

    public String getAuthenticationMethod() { return authenticationMethod; }
    public void setAuthenticationMethod(String authenticationMethod) { this.authenticationMethod = authenticationMethod; }

    public String getDateTime() { return dateTime; }
    public void setDateTime(String dateTime) { this.dateTime = dateTime; }

    public Boolean getIsAuthenticated() { return isAuthenticated; }
    public void setIsAuthenticated(Boolean isAuthenticated) { this.isAuthenticated = isAuthenticated; }

    public String getAuthenticationMethods() { return authenticationMethods; }
    public void setAuthenticationMethods(String authenticationMethods) { this.authenticationMethods = authenticationMethods; }

    public String getTxnID() { return txnID; }
    public void setTxnID(String txnID) { this.txnID = txnID; }

    public Integer getResponseCode() { return responseCode; }
    public void setResponseCode(Integer responseCode) { this.responseCode = responseCode; }

    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }

    public static final class Builder {
        private final TicketPayload payload = new TicketPayload();

        public Builder systemCode(String v) { payload.systemCode = v; return this; }
        public Builder institutionCode(String v) { payload.institutionCode = v; return this; }
        public Builder userId(String v) { payload.userId = v; return this; }
        public Builder email(String v) { payload.email = v; return this; }
        public Builder fullName(String v) { payload.fullName = v; return this; }
        public Builder mobile(String v) { payload.mobile = v; return this; }
        public Builder dateTime(String v) { payload.dateTime = v; return this; }

        public TicketPayload build() { return payload; }
    }
}
