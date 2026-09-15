from __future__ import annotations
import hashlib
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.record import TLS


def _ids(values) -> list[int]:
    out=[]
    for x in values or []:
        try: out.append(int(getattr(x, 'val', x)))
        except (TypeError, ValueError): pass
    return out


def tls_metadata(packet) -> dict | None:
    """Extract passive TLS ClientHello metadata; never decrypts payloads."""
    if TLS not in packet or TLSClientHello not in packet:
        return None
    ch=packet[TLSClientHello]
    ciphers=_ids(getattr(ch, 'ciphers', []))
    exts=getattr(ch, 'ext', []) or []
    ext_ids=[]; groups=[]; points=[]; sni=None
    for ext in exts:
        eid=getattr(ext, 'type', None)
        if eid is not None:
            try: ext_ids.append(int(eid))
            except (TypeError, ValueError): pass
        name=ext.__class__.__name__.lower()
        if 'servernam' in name:
            servernames=getattr(ext, 'servernames', []) or []
            if servernames:
                sni=getattr(servernames[0], 'servername', None)
                if isinstance(sni, bytes): sni=sni.decode(errors='ignore')
        if hasattr(ext, 'groups'): groups=_ids(getattr(ext,'groups',[]))
        if hasattr(ext, 'ec_point_formats'): points=_ids(getattr(ext,'ec_point_formats',[]))
    version=getattr(ch,'version',0)
    try: version=int(getattr(version,'val',version))
    except (TypeError,ValueError): version=0
    ja3_string=','.join(map(str,[version]))+'|'+','.join(map(str,ciphers))+'|'+','.join(map(str,ext_ids))+'|'+','.join(map(str,groups))+'|'+','.join(map(str,points))
    return {'sni': sni, 'tls_version': version, 'cipher_count': len(ciphers), 'extension_count': len(ext_ids),
            'ja3': hashlib.md5(ja3_string.encode()).hexdigest(), 'ja3_string': ja3_string}


def quic_metadata(packet) -> dict | None:
    """Passive QUIC metadata heuristic for UDP/443; no payload decryption."""
    from scapy.layers.inet import UDP
    if UDP not in packet or int(packet[UDP].dport) != 443:
        return None
    payload=bytes(packet[UDP].payload)
    if len(payload)<5: return None
    # QUIC long-header packets have the header form bit set and version follows.
    if payload[0] & 0x80:
        version=int.from_bytes(payload[1:5],'big')
        return {'long_header': True, 'version': version, 'payload_bytes': len(payload)}
    return {'long_header': False, 'payload_bytes': len(payload)}
