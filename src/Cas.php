<?php
namespace PhpCasCore;

use DOMNodeList;

class Cas
{
    private $_user;

    private $_cas_server;

    private $_cas_path;

    private $_attributes = array();

    private static $cas_client = null;

    public function __construct(string $cas_server, string $cas_path)
    {
        $this->_cas_path = $cas_path;
        $this->_cas_server = $cas_server;
        if (empty($cas_server)) {
            self::$cas_client = new \phpCAS();
        }
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
        $url = $this->getURL($url);
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
                $user =
                    trim(
                        $success_elements->item(0)->getElementsByTagName("user")->item(0)->nodeValue
                    );
                $this->_user = $user;
                return $user;
            }
        } else {
            throw new \Exception(
                'Ticket not validated'. $validate_url
            );
        }
    }



    /**
     * Set an array of attributes
     *
     * @param array $attributes a key value array of attributes
     *
     * @return void
     */
    public function setAttributes($attributes)
    {
        $this->_attributes = $attributes;
    }

    /**
     * This method will parse the DOM and pull out the attributes from the XML
     * payload and put them into an array, then put the array into the session.
     *
     * @param DOMNodeList $success_elements payload of the response
     *
     * @return bool true when successfull, halt otherwise by calling
     * CAS_Client::_authError().
     */
    private function _readExtraAttributesCas20($success_elements)
    {
        $extra_attributes = array();

        if ( $success_elements->item(0)->getElementsByTagName("attributes")->length != 0) {
            $attr_nodes = $success_elements->item(0)
                ->getElementsByTagName("attributes");
            if ($attr_nodes->item(0)->hasChildNodes()) {
                // Nested Attributes
                foreach ($attr_nodes->item(0)->childNodes as $attr_child) {
                    $this->_addAttributeToArray(
                        $extra_attributes, $attr_child->localName,
                        $attr_child->nodeValue
                    );
                }
            }
        } else {
            $childnodes = $success_elements->item(0)->childNodes;
            foreach ($childnodes as $attr_node) {
                switch ($attr_node->localName) {
                    case 'user':
                    case 'proxies':
                    case 'proxyGrantingTicket':
                        break;
                    default:
                        if (strlen(trim($attr_node->nodeValue))) {
                            $this->_addAttributeToArray(
                                $extra_attributes, $attr_node->localName,
                                $attr_node->nodeValue
                            );
                        }
                }
            }
        }

        if (!count($extra_attributes)
            && $success_elements->item(0)->getElementsByTagName("attribute")->length != 0
        ) {
            $attr_nodes = $success_elements->item(0)
                ->getElementsByTagName("attribute");
            $firstAttr = $attr_nodes->item(0);
            if (!$firstAttr->hasChildNodes()
                && $firstAttr->hasAttribute('name')
                && $firstAttr->hasAttribute('value')
            ) {
                // Nested Attributes
                foreach ($attr_nodes as $attr_node) {
                    if ($attr_node->hasAttribute('name')
                        && $attr_node->hasAttribute('value')
                    ) {
                        $this->_addAttributeToArray(
                            $extra_attributes, $attr_node->getAttribute('name'),
                            $attr_node->getAttribute('value')
                        );
                    }
                }
            }
        }
        $this->setAttributes($extra_attributes);
        return true;
    }

    /**
     * Add an attribute value to an array of attributes.
     *
     * @param array  &$attributeArray reference to array
     * @param string $name            name of attribute
     * @param string $value           value of attribute
     *
     * @return void
     */
    private function _addAttributeToArray(array &$attributeArray, $name, $value)
    {
        // If multiple attributes exist, add as an array value
        if (isset($attributeArray[$name])) {
            // Initialize the array with the existing value
            if (!is_array($attributeArray[$name])) {
                $existingValue = $attributeArray[$name];
                $attributeArray[$name] = array($existingValue);
            }

            $attributeArray[$name][] = trim($value);
        } else {
            $attributeArray[$name] = trim($value);
        }
    }

    private function _removeParameterFromQueryString($parameterName, $queryString)
    {
        $parameterName	= preg_quote($parameterName);
        return preg_replace(
            "/&$parameterName(=[^&]*)?|^$parameterName(=[^&]*)?&?/",
            '', $queryString
        );
    }

    public function getURL($request_uri)
    {
        $request_uri	= explode('?', $request_uri, 2);
        $final_uri		= $request_uri[0];

        if (isset($request_uri[1]) && $request_uri[1]) {
            $query_string= $this->_removeParameterFromQueryString('ticket', $request_uri[1]);

            // If the query string still has anything left,
            // append it to the final URI
            if ($query_string !== '') {
                $final_uri	.= "?$query_string";
            }
        }
        return $final_uri;
    }

    /**
     * 单点登录
     * @param Request $request
     */
    public function casLogout(string $url = null)
    {
        if ($url) {
            getGouuseCore()->ResponseLib->redirect($this->_cas_server.$this->_cas_path."/logout?service=".urlencode($url));
        } else {
            getGouuseCore()->ResponseLib->redirect($this->_cas_server.$this->_cas_path."/logout");
        }
    }
}