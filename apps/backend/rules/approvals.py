"""Decide qué roles pueden autorizar una propuesta de contención."""
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
import re

from apps.backend.tools import db

DUAL_USE = ("mega.nz", "anydesk.com", "wetransfer.com")
REQUIRES_N2 = {"revoke_sessions", "reset_password", "disable_user", "disable_access_key"}
IOC_DOMAIN = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]*")
IOC_HASH = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class ApprovalPolicy:
    permitted: bool
    roles: tuple[str, ...]
    reason: str


def _address(target: str):
    try:
        address = ip_address(target)
    except ValueError:
        return None
    return getattr(address, "ipv4_mapped", None) or address


def is_ot(target: str, asset: dict | None = None) -> bool:
    if asset and asset["zone"] == "LOGISTICS-OT":
        return True
    address = _address(target)
    return address is not None and any(
        address in ip_network(zone["cidr"]) for zone in db.network_zones("LOGISTICS-OT")
    )


def aprobacion(action: str, target: str) -> ApprovalPolicy:
    target = target.strip().lower().rstrip(".")
    if not target:
        return ApprovalPolicy(False, (), "Falta el objetivo de la acción.")
    asset = db.asset(target)
    if is_ot(target, asset):
        return ApprovalPolicy(False, ("Responsable de Operaciones",), "La política limita OT al escalado.")
    if action == "isolate_host":
        if not asset:
            return ApprovalPolicy(False, (), "El objetivo debe estar identificado en la CMDB.")
        asset_type = asset["type"]
        if asset_type in {"TPV", "Frontal web", "Pasarela de pagos"}:
            return ApprovalPolicy(True, ("N2", "Negocio"), "Impacto directo en ventas.")
        if asset_type not in {"Portátil", "Sobremesa"}:
            return ApprovalPolicy(True, ("N2", "Responsable del servicio"), "Aislamiento de servidor.")
        return ApprovalPolicy(True, ("N2",), "Aislamiento de puesto de trabajo.")
    if action in REQUIRES_N2:
        return ApprovalPolicy(True, ("N2",), "Acción disruptiva.")
    if action == "block_ioc" and not (_address(target) or IOC_DOMAIN.fullmatch(target) or IOC_HASH.fullmatch(target)):
        return ApprovalPolicy(False, (), "El indicador debe ser una IP, un dominio o un SHA-256.")
    if action == "block_ioc" and any(target == host or target.endswith("." + host) for host in DUAL_USE):
        return ApprovalPolicy(True, ("N2",), "Servicio de uso dual.")
    if action in {"block_ioc", "purge_email"}:
        return ApprovalPolicy(True, ("N1",), "Acción permitida a un operador N1.")
    return ApprovalPolicy(False, (), "Acción ajena a la política de Tarvia.")
