package burp;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, IScannerCheck ,IHttpRequestResponse, IRequestInfo, IHttpListener, IProxyListener, IScannerListener, IExtensionStateListener {

    /**
     *
     * Variables
     */

    private IBurpExtenderCallbacks callbacks;
    private String author = "incogbyte";
    private String ExtensionName = "wordpress hook users";

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        callbacks.setExtensionName(ExtensionName);
        callbacks.issueAlert(author);
        this.callbacks = callbacks;

        callbacks.registerHttpListener(this);
        callbacks.registerProxyListener(this);
        callbacks.registerScannerListener(this);
        callbacks.registerScannerCheck(this);
        callbacks.registerExtensionStateListener(this);
    }


    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse responseOfReq) {
        if (messageIsRequest) {
            return;
        }

        if(toolFlag != 4) {
            return;
        }

        String host = responseOfReq.getHttpService().getHost().toString();
        byte[] UrlContent = responseOfReq.getResponse();
        String s = new String(UrlContent);
        System.out.println("> HOST: " + host);

    }

    public boolean isWordpress(String contentSite) {
        if (contentSite.contains("wp-content") || contentSite.contains("wp-inclues") || contentSite.contains("wpemojiSetting")) {
            System.out.println("> Wordpress found");
            return true; //if site runs wordpress
        }
        return false;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {

        List<IScanIssue> issues = new ArrayList<IScanIssue>();

        byte[] reponseBytes = baseRequestResponse.getResponse();
        String resp = callbacks.getHelpers().bytesToString(reponseBytes);

        if(isWordpress(resp)) {
            issues.add(
                            new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            callbacks.getHelpers().analyzeRequest(baseRequestResponse).getUrl(),
                            new IHttpRequestResponse[] { baseRequestResponse },
                            "Wordpress found",
                            "A instance of wordpress was found",
                            "",
                            "Firm",
                            "Information"));
        }
        return issues;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
       if(existingIssue.getIssueDetail().equals(newIssue.getIssueDetail())) {
           return -1;
       } else {
           return 0;
       }
    }

    class CustomScanIssue implements IScanIssue {
        private IHttpService httpService;
        private URL url;
        private IHttpRequestResponse[] httpMessages;
        private String name;
        private String detail;
        private String remediation;
        private String severity;
        private String confidence;

        public CustomScanIssue (IHttpService httpService, URL url, IHttpRequestResponse[] httpMessages, String name, String detail,  String remediation, String confidence,String severity) {
            this.httpService = httpService;
            this.url = url;
            this.httpMessages = httpMessages;
            this.name = name;
            this.detail = detail;
            this.remediation = remediation;
            this.severity = severity;
            this.confidence = confidence;
        }

        @Override
        public URL getUrl() {
            return url;
        }

        @Override
        public String getIssueName() {
            return name;
        }

        @Override
        public int getIssueType() {
            return 0;
        }

        @Override
        public String getSeverity() {
            return severity;
        }

        @Override
        public String getConfidence() {
            return confidence;
        }

        @Override
        public String getIssueBackground() {
            return null;
        }

        @Override
        public String getRemediationBackground() {
            return null;
        }

        @Override
        public String getIssueDetail() {
            return detail;
        }

        @Override
        public String getRemediationDetail() {
            return remediation;
        }

        @Override
        public IHttpRequestResponse[] getHttpMessages() {
            return httpMessages;
        }

        @Override
        public IHttpService getHttpService() {
            return httpService;
        }

    }


    @Override
    public byte[] getRequest() {
        return new byte[0];
    }

    @Override
    public void setRequest(byte[] message) {

    }

    @Override
    public byte[] getResponse() {
        return new byte[0];
    }

    @Override
    public void setResponse(byte[] message) {

    }

    @Override
    public String getComment() {
        return null;
    }

    @Override
    public void setComment(String comment) {

    }

    @Override
    public String getHighlight() {
        return null;
    }

    @Override
    public void setHighlight(String color) {

    }

    @Override
    public IHttpService getHttpService() {
        return null;
    }

    @Override
    public void setHttpService(IHttpService httpService) {

    }


    @Override
    public String getMethod() {
        return null;
    }

    @Override
    public URL getUrl() {
        return null;
    }


    @Override
    public List<String> getHeaders() {
        return null;
    }

    @Override
    public List<IParameter> getParameters() {
        return null;
    }

    @Override
    public int getBodyOffset() {
        return 0;
    }

    @Override
    public byte getContentType() {
        return 0;
    }


    @Override
    public void extensionUnloaded() {

    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {

    }

    @Override
    public void newScanIssue(IScanIssue issue) {

    }
}
