# dmss_poc

PoC Rust aislada para reproducir el flujo remoto de DMSS fuera de la app móvil.

Estado actual:
1. `bootstrap` funcional:
   - `probe/p2psrv`
   - `online/p2psrv/{serial}`
   - `online/relay`
   - `probe/device/{serial}`
   - `info/device/{serial}`
   - `device/{serial}/p2p-channel`
2. Construcción moderna del body `p2p-channel`:
   - `CreateDate`
   - `DevAuth`
   - `Nonce`
   - `RandSalt`
   - `UserName`
   - `Identify`
   - `IpEncrptV2`
   - `LocalAddr`
   - `version`
   - `sVersion`
   - `NatValueT`
   - `Pid`
   - `ClientId`
3. Parseo de `Server Nat Info!`

Pendiente:
1. STUN/ICE-like
2. PTCP sync/session
3. Login realm challenge/response
4. `PLAY /live/realmonitor.xav`
5. Persistencia de `video/e-xav`

Ejemplo:

```bash
cargo run -- bootstrap \
  --serial 7H0265FPAZC8CA3 \
  --device-user admin \
  --device-password 'YOUR_PASSWORD'
```
