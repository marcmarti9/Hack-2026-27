"""Quién aprueba cada contención (politica_soc.md, apartado 4)."""
DUAL_USE = ("mega.nz", "anydesk.com", "wetransfer.com")

def aprobacion(accion: str, objetivo: str, asset: dict | None = None) -> dict:
    """Devuelve {'permitido': bool, 'requiere': [...], 'nota': str}."""
    zona = (asset or {}).get("zone", "")
    tipo = (asset or {}).get("type", "")
    if zona == "LOGISTICS-OT":
        return {"permitido": False, "requiere": ["Responsable de Operaciones"], "nota": "El SOC nunca actúa sobre OT: solo escalar"}
    if accion == "purge_email":
        return {"permitido": True, "requiere": [], "nota": "El N1 puede ejecutarlo"}
    if accion == "block_ioc":
        if any(objetivo.lower().endswith(d) for d in DUAL_USE):
            return {"permitido": True, "requiere": ["N2"], "nota": "Servicio legítimo de uso dual: no bloquear globalmente sin N2"}
        return {"permitido": True, "requiere": [], "nota": "El N1 puede ejecutarlo"}
    if accion == "isolate_host":
        if tipo in ("TPV", "Frontal web", "Pasarela de pagos"):
            return {"permitido": True, "requiere": ["N2", "Negocio"], "nota": "Impacto directo en ventas"}
        if tipo and tipo not in ("Portátil", "Sobremesa"):
            return {"permitido": True, "requiere": ["N2", "Responsable del servicio"], "nota": f"Servidor: {asset.get('business_service', '')}"}
        return {"permitido": True, "requiere": ["N2"], "nota": "Puesto de trabajo"}
    if accion in ("revoke_sessions", "reset_password", "disable_user", "disable_access_key"):
        return {"permitido": True, "requiere": ["N2"], "nota": "Una cuenta de servicio puede parar un proceso de negocio" if accion == "disable_user" else ""}
    return {"permitido": False, "requiere": ["N2"], "nota": f"Acción no contemplada: {accion}"}
