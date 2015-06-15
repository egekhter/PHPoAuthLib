<?php
namespace OAuth\OAuth2\Service;
use OAuth\OAuth2\Token\StdOAuth2Token;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
class Yahoo extends AbstractService
{
    /**
     * {@inheritdoc}
     */
    public function getAuthorizationEndpoint()
    {
        return new Uri('https://api.login.yahoo.com/oauth2/request_auth');
    }
    /**
     * {@inheritdoc}
     */
    public function getAccessTokenEndpoint()
    {
        return new Uri('https://api.login.yahoo.com/oauth2/get_token');
    }
    /**
     * {@inheritdoc}
     */
    protected function getAuthorizationMethod()
    {
        return static::AUTHORIZATION_METHOD_HEADER_BEARER;
    }
    /**
     * {@inheritdoc}
     */
    protected function parseAccessTokenResponse($responseBody)
    {
        $data = json_decode($responseBody, true);
        if (null === $data || !is_array($data))
        {
            throw new TokenResponseException('Unable to parse response.');
        } elseif (isset($data['error']))
        {
            throw new TokenResponseException('Error in retrieving token: "' . $data['error'] . '"');
        }
        $token = new StdOAuth2Token();
        $token->setAccessToken($data['access_token']);
        $token->setLifetime($data['expires_in']);
        if (isset($data['refresh_token']))
        {
            $token->setRefreshToken($data['refresh_token']);
            unset($data['refresh_token']);
        }
        unset($data['access_token']);
        unset($data['expires_in']);
        $token->setExtraParams($data);
        return $token;
    }
    /**
     * {@inheritdoc}
     */
    protected function getExtraOAuthHeaders()
    {
        $encodedCredentials = base64_encode($this->credentials->getConsumerId() . ':' . $this->credentials->getConsumerSecret());
        return ['Authorization' => 'Basic ' . $encodedCredentials];
    }

    public function requestAccessToken($code, $state = null)
    {
        if (null !== $state) {
            $this->validateAuthorizationState($state);
        }
        $bodyParams = array(
            'code'          => $code,
            'client_id'     => $this->credentials->getConsumerId(),
            'client_secret' => $this->credentials->getConsumerSecret(),
            'redirect_uri'  => $this->credentials->getCallbackUrl(),
            'grant_type'    => 'authorization_code',
        );
        $responseBody = $this->httpClient->retrieveResponse(
            $this->getAccessTokenEndpoint(),
            $bodyParams,
            $this->getExtraOAuthHeaders()
        );
        // we can scream what we want that we want bitly to return a json encoded string (format=json), but the
        // WOAH WATCH YOUR LANGUAGE ;) service doesn't seem to like screaming, hence we need to manually
        // parse the result
        $parsedResult = array();
        parse_str($responseBody, $parsedResult);
        $token = $this->parseAccessTokenResponse(json_encode($parsedResult));
        $this->storage->storeAccessToken($this->service(), $token);
        return $token;
    }

//    public function refreshAccessToken2(TokenInterface $token)
//    {
//        $refreshToken = $token->getRefreshToken();
//        if (empty($refreshToken)) {
//            throw new MissingRefreshTokenException();
//        }
//        $parameters = array(
//            'grant_type'    => 'refresh_token',
//            'type'          => 'web_server',
//            'client_id'     => $this->credentials->getConsumerId(),
//            'client_secret' => $this->credentials->getConsumerSecret(),
//            'refresh_token' => $refreshToken,
//        );
//        $responseBody = $this->httpClient->retrieveResponse(
//            $this->getAccessTokenEndpoint(),
//            $parameters,
//            $this->getExtraOAuthHeaders()
//        );
//        $token = $this->parseAccessTokenResponse($responseBody);
//        $this->storage->storeAccessToken($this->service(), $token);
//        return $token;
//    }
}