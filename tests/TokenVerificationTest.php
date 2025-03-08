<?php


use Jumbojett\OpenIDConnectClient;
use Jumbojett\OpenIDConnectClientException;
use PHPUnit\Framework\MockObject\MockObject;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class TokenVerificationTest extends TestCase
{
    /**
     * @param $alg
     * @param $jwt
     * @throws OpenIDConnectClientException
     * @dataProvider providesTokens
     */
    public function testTokenVerification($alg, $jwt)
    {
        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['fetchUrl'])->getMock();
        $client->method('fetchUrl')->willReturn(file_get_contents(__DIR__ . "/data/jwks-$alg.json"));
        $client->setProviderURL('https://jwt.io/');
        $client->providerConfigParam(['jwks_uri' => 'https://jwt.io/.well-known/jwks.json']);
        $verified = $client->verifyJWTSignature($jwt);
        self::assertTrue($verified);
        $client->setAccessToken($jwt);
    }

    public function providesTokens(): array
    {
        return [
            'PS256' => ['ps256', 'eyJhbGciOiJQUzI1NiIsImtpZCI6Imtvbm5lY3RkLXRva2Vucy1zaWduaW5nLWtleSIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJrcG9wLWh0dHBzOi8va29wYW5vLmRlbW8vbWVldC8iLCJleHAiOjE1NjgzNzE0NjEsImp0aSI6IkpkR0tDbEdOTXl2VXJpcmlRRUlWUXZCVmttT2FfQkRjIiwiaWF0IjoxNTY4MzcxMjIxLCJpc3MiOiJodHRwczovL2tvcGFuby5kZW1vIiwic3ViIjoiUHpUVWp3NHBlXzctWE5rWlBILXJxVHE0MTQ1Z3lDdlRvQmk4V1E5bFBrcW5rbEc1aktvRU5LM21Qb0I1WGY1ZTM5dFRMR2RKWXBMNEJubXFnelpaX0FAa29ubmVjdCIsImtjLmlzQWNjZXNzVG9rZW4iOnRydWUsImtjLmF1dGhvcml6ZWRTY29wZXMiOlsicHJvZmlsZSIsImVtYWlsIiwia29wYW5vL2t3bSIsImtvcGFuby9nYyIsImtvcGFuby9rdnMiLCJvcGVuaWQiXSwia2MuYXV0aG9yaXplZENsYWltcyI6eyJpZF90b2tlbiI6eyJuYW1lIjpudWxsfX0sImtjLmlkZW50aXR5Ijp7ImtjLmkuZG4iOiJKb25hcyBCcmVra2UiLCJrYy5pLmlkIjoiQUFBQUFLd2hxVkJBMCs1SXN4bjdwMU13UkNVQkFBQUFCZ0FBQUJzQUFBQk5VVDA5QUFBQUFBPT0iLCJrYy5pLnVuIjoidXNlcjEiLCJrYy5pLnVzIjoiTVEifSwia2MucHJvdmlkZXIiOiJpZGVudGlmaWVyLWtjIn0.hGRuXvul2kOiALHexwYp5MBEJVwz1YV3ehyM3AOuwCoK2w5sJxdciqqY_TfXCKyO6nAEbYLK3J0CBOjfup_IG0aCZcwzjto8khYlc4ezXkGnFsbJBNQdDGkpHtWnioWx-OJ3cXvY9F8aOvjaq0gw11ZDAcqQl0g7LTbJ9-J_yx0pmy3NGai2JB30Fh1OgSDzYfxWnE0RRgZG-x68e65RXfSBaEGW85OUh4wihxO2zdTGAHJ3Iq_-QAG4yRbXZtLx3ZspG7LNmqG-YE3huy3Rd8u3xrJNhmUOfEnz3x07q7VW0cj9NedX98BAbj3iNvksQsE0oG0J_f_Tu8Ai8VbWB72sJuXZWxANDKdz0BBYLzXhsjXkNByRq9x3zqDVsX-cVHei_XudxEOVRBjhkvW2MmIjcAHNKCKsdar865-gFG9McP4PCcBlY28tC0Cvnzyi83LBfpGRXdl6MJunnUsKQ1C79iCoVI1doK1erFN959Q-TGJfJA3Tr5LNpuGawB5rpe1nDGWvmYhg3uYfNl8uTTyvNgvvejcflEb2DURuXdqABuSiP7RkDWYtzx6mq49G0tRxelBbvyjQ2id2QjmRRdQ6dHEZ2NCJ51b8OFoDJBtxN1CD62TTxa3FUqCdZAPAUR3hHn_69vYq82MR514s-Gb67A6j2PbMPFATQP2UdK8'],
            'RS512' => ['rs512', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiIsImtpZCI6IjNiNGI3ZmNiYWM4MTAwZmU1Mjg5MTI3NzY0MTcwMDlhIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.rBovVXkUymQRHeTolWO07nJyw2NJgho8JbyjPAbZ2VAcQKvrjL8SNrkIkdjuI4FDfJQvu_NOlsKu0LhGNUJATxQhGvFqWOfF9nggFtl7ZTpAu3E6Xm1s-VGSy9LOQvmBiFvXDQJ7bd0xn0Ld1XO2lIVLHItoPr6Gw1m0_vdtUlMrX_dF4ZrJCBaQWXw114zgwH4WIZ8nvvDRdw3n1FLvPrYFZzRBI0Z8wXkBVEnw_kxlQWi7waOp-5NwZFYF5Tei1KUDQMSUcxAckNh01it8UdHoQf4HhgRF_GeDi9HJRVPUCO4N1wVtKRVqDMKRvQxZCn-_ohsUHA2u1-CUakbsd1EDkP8SaPFtvtW0QKB7K3KWQVSHUh7Kp6cct4scbDCGzXPwrgGyKF9V3d1g4fed6epkFlFnif0ZM9JvMSp7ult40HdC7D-9YCdJ39d5T2RGVOeQEKEk0UqxanG-dbp2RmjMYms70h75XatR7Bfbt1bsDB0dwnEwbwFLps1H_dVS'],
            'EdDSA' => ['eddsa', 'eyJraWQiOiItMTkwOTU3MjI1NyIsImFsZyI6IkVkRFNBIn0.eyJqdGkiOiIyMjkxNmYzYy05MDkzLTQ4MTMtODM5Ny1mMTBlNmI3MDRiNjgiLCJkZWxlZ2F0aW9uSWQiOiJiNGFlNDdhNy02MjVhLTQ2MzAtOTcyNy00NTc2NGE3MTJjY2UiLCJleHAiOjE2NTUyNzkxMDksIm5iZiI6MTY1NTI3ODgwOSwic2NvcGUiOiJyZWFkIG9wZW5pZCIsImlzcyI6Imh0dHBzOi8vaWRzdnIuZXhhbXBsZS5jb20iLCJzdWIiOiJ1c2VybmFtZSIsImF1ZCI6ImFwaS5leGFtcGxlLmNvbSIsImlhdCI6MTY1NTI3ODgwOSwicHVycG9zZSI6ImFjY2Vzc190b2tlbiJ9.rjeE8D_e4RYzgvpu-nOwwx7PWMiZyDZwkwO6RiHR5t8g4JqqVokUKQt-oST1s45wubacfeDSFogOrIhe3UHDAg']
        ];
    }
}
