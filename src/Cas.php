<?php
namespace PhpCasCore;

class Cas
{
    private $_user;

    private $_cas_server;

    private $_cas_path;

    public function __construct(string $cas_server, string $cas_path)
    {
        $this->_cas_path = $cas_path;
        $this->_cas_server = $cas_server;
        $cas = new \phpCAS();
    }


    private function _buildSAMLPayload($ticket)
    {
        $sa = urlencode($ticket);

        $body = SAML_SOAP_ENV.SAML_SOAP_BODY.SAMLP_REQUEST
            .SAML_ASSERTION_ARTIFACT.$sa.SAML_ASSERTION_ARTIFACT_CLOSE
            .SAMLP_REQUEST_CLOSE.SAML_SOAP_BODY_CLOSE.SAML_SOAP_ENV_CLOSE;

        return ($body);
    }


    private function serviceValidate($url, $ticket) {

        $validate_url = $this->_cas_server . $this->_cas_path . "/serviceValidate?service=".urlencode($url)."&ticket=".urlencode($ticket);
        $client = new GuzzleClient(['base_uri' => $this->_cas_server, 'timeout' => 10.0]);
        $form_params = [
            'body' => $this->_buildSAMLPayload($ticket),
            'http_errors' => false,
            'headers' => [
                'soapaction:http://www.oasis-open.org/committees/security',
                "cache-control:no-cache",
                "pragma:no-cache",
                "accept:text/xml",
                "connection:keep-alive",
                "content-type:text/xml"
            ]
        ];
        $response = $client->request('POST', $validate_url, $form_params);
        $text_response = $response->getBody()->getContents();

        $dom = new DOMDocument();
        // Fix possible whitspace problems
        $dom->preserveWhiteSpace = false;
        // CAS servers should only return data in utf-8
        $dom->encoding = "utf-8";
        // read the response of the CAS server into a DOMDocument object
        if ( !($dom->loadXML($text_response))) {
            // read failed
            throw new \Exception(
                'Ticket not validated'. $validate_url
            );
        } else if ( !($tree_response = $dom->documentElement) ) {
            // read the root node of the XML tree
            // read failed
            throw new \Exception(
                'Ticket not validated'. $validate_url
            );
        } else if ($tree_response->localName != 'serviceResponse') {
            // insure that tag name is 'serviceResponse'
            // bad root node
            throw new \Exception(
                'Ticket not validated'. $validate_url
            );
        } else if ( $tree_response->getElementsByTagName("authenticationFailure")->length != 0) {
            // authentication failed, extract the error code and message and throw exception
            $auth_fail_list = $tree_response
                ->getElementsByTagName("authenticationFailure");
            throw new \Exception(
                'Ticket not validated'. $validate_url
            );
        } else if ($tree_response->getElementsByTagName("authenticationSuccess")->length != 0) {
            // authentication succeded, extract the user name
            $success_elements = $tree_response
                ->getElementsByTagName("authenticationSuccess");
            if ( $success_elements->item(0)->getElementsByTagName("user")->length == 0) {
                // no user specified => error
                throw new \Exception(
                    'Ticket not validated'. $validate_url
                );
            } else {
                return
                    trim(
                        $success_elements->item(0)->getElementsByTagName("user")->item(0)->nodeValue
                    );
            }
        } else {
            throw new \Exception(
                'Ticket not validated'. $validate_url
            );
        }

    }

    /**
     * 单点登录
     * @param Request $request
     */
    public function casLogout(string $url)
    {
        getGouuseCore()->ResponseLib->redirect($this->_cas_server.$this->_cas_path."/logout?service=".urlencode($url));
    }
}