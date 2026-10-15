# Security

Please report a security problem in this client, or in EyalSec itself, to **security@eyalsec.com** rather than in a public issue. We will reply to confirm we have it and keep you updated until it is fixed. The EyalSec security page is at <https://eyalsec.com/security>.

This library sends your API key only to the address you configure, only over HTTPS (plain HTTP is accepted for `localhost` alone), and never includes it in a `repr` or an error message.
