"""Standard service metadata schema shared across every m8 service.

Pure Pydantic — no FastAPI import — so non-web SDK users can build/validate a
``ServiceMeta`` without pulling the ``fastapi`` extra. The mountable router that
serves it lives in :mod:`auth_sdk_m8.controllers.meta`.
"""

from pydantic import BaseModel, Field


class ServiceContract(BaseModel):
    """Identity of the contract a service implements."""

    name: str = Field(min_length=1, description="Contract name.")
    version: str = Field(min_length=1, description="Contract version.")
    range: str = Field(min_length=1, description="Compatible semver range.")


class ServiceMeta(BaseModel):
    """Public, minimal service identity for client compatibility checks.

    Exposed at ``{API_PREFIX}/meta`` so clients can assert compatibility before
    authenticating. Carries only service/version/contract — never build paths,
    hostnames, dependency internals, or secrets.
    """

    service: str = Field(min_length=1, description="Service name.")
    version: str = Field(min_length=1, description="Service package version.")
    api_version: str = Field(min_length=1, description="API version, e.g. 'v1'.")
    contract: ServiceContract = Field(description="Contract identity.")
