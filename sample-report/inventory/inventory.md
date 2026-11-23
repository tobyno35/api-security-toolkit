# Authorized asset inventory

Accepted assets: 5; rejected records: 3

| Kind | Asset | Evidence references |
| --- | --- | --- |
| domain | api.example.test | dnsx:f031c01efe6db3136b60ecb1aba2e3bcd92c066a19f22e6f1a150b94df5e4740#1, httpx:6a2d0e74ae5a1edc97eedbd9cd0ddda110be82aaafb0d73ac356ef4fdf50695e#1, httpx:6a2d0e74ae5a1edc97eedbd9cd0ddda110be82aaafb0d73ac356ef4fdf50695e#2, subfinder:9f3d1210b9c8263f04d38deba4d55b2b4e21415e72cd4f246864aa5adf026237#1, subfinder:9f3d1210b9c8263f04d38deba4d55b2b4e21415e72cd4f246864aa5adf026237#2 |
| endpoint | https://api.example.test/ | httpx:6a2d0e74ae5a1edc97eedbd9cd0ddda110be82aaafb0d73ac356ef4fdf50695e#1 |
| endpoint | https://api.example.test/v1 | httpx:6a2d0e74ae5a1edc97eedbd9cd0ddda110be82aaafb0d73ac356ef4fdf50695e#2 |
| ip | 192.0.2.10 | dnsx:f031c01efe6db3136b60ecb1aba2e3bcd92c066a19f22e6f1a150b94df5e4740#1, httpx:6a2d0e74ae5a1edc97eedbd9cd0ddda110be82aaafb0d73ac356ef4fdf50695e#1, httpx:6a2d0e74ae5a1edc97eedbd9cd0ddda110be82aaafb0d73ac356ef4fdf50695e#2 |
| ip | 2001:db8::10 | dnsx:f031c01efe6db3136b60ecb1aba2e3bcd92c066a19f22e6f1a150b94df5e4740#1 |

## Rejected records

- {&quot;assets&quot;: [{&quot;kind&quot;: &quot;domain&quot;, &quot;value&quot;: &quot;outside.test&quot;}, {&quot;kind&quot;: &quot;endpoint&quot;, &quot;value&quot;: &quot;https://outside.test/&quot;}], &quot;reason&quot;: &quot;out_of_scope&quot;, &quot;record&quot;: 3, &quot;source&quot;: &quot;httpx:6a2d0e74ae5a1edc97eedbd9cd0ddda110be82aaafb0d73ac356ef4fdf50695e&quot;}
- {&quot;assets&quot;: [{&quot;kind&quot;: &quot;domain&quot;, &quot;value&quot;: &quot;outside.test&quot;}], &quot;reason&quot;: &quot;out_of_scope&quot;, &quot;record&quot;: 3, &quot;source&quot;: &quot;subfinder:9f3d1210b9c8263f04d38deba4d55b2b4e21415e72cd4f246864aa5adf026237&quot;}
- {&quot;assets&quot;: [{&quot;kind&quot;: &quot;ip&quot;, &quot;value&quot;: &quot;203.0.113.9&quot;}], &quot;reason&quot;: &quot;out_of_scope&quot;, &quot;record&quot;: 2, &quot;source&quot;: &quot;dnsx:f031c01efe6db3136b60ecb1aba2e3bcd92c066a19f22e6f1a150b94df5e4740&quot;}
