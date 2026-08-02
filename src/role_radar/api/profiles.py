"""Router de perfiles versionados."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.exc import IntegrityError

from role_radar.api.deps import get_profile_repository
from role_radar.api.schemas.profiles import ProfileCreate, ProfileResponse, ProfileUpdate
from role_radar.repositories.profiles import ProfileRepository

router = APIRouter(prefix="/profiles", tags=["profiles"])


@router.post("", response_model=ProfileResponse, status_code=201)
def create_profile(
    payload: ProfileCreate,
    repo: Annotated[ProfileRepository, Depends(get_profile_repository)],
) -> ProfileResponse:
    """Crea un perfil candidato (API escribe perfiles — política §11)."""
    if any(profile.name == payload.name for profile in repo.list_all()):
        raise HTTPException(status_code=409, detail="Profile name already exists")
    profile = repo.create_v1(
        name=payload.name, profile_json=payload.profile_json.model_dump(mode="json")
    )
    return ProfileResponse.model_validate(profile)


@router.put("/{profile_id}", response_model=ProfileResponse)
def update_profile(
    profile_id: str,
    payload: ProfileUpdate,
    repo: Annotated[ProfileRepository, Depends(get_profile_repository)],
) -> ProfileResponse:
    try:
        profile = repo.create_version(profile_id, payload.profile_json.model_dump(mode="json"))
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="Profile not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except IntegrityError as exc:
        raise HTTPException(status_code=409, detail="Profile version already exists") from exc
    return ProfileResponse.model_validate(profile)


@router.get("", response_model=list[ProfileResponse])
def list_profiles(
    repo: Annotated[ProfileRepository, Depends(get_profile_repository)],
) -> list[ProfileResponse]:
    """Lista perfiles activos."""
    return [ProfileResponse.model_validate(p) for p in repo.list_active()]


@router.get("/{profile_id}", response_model=ProfileResponse)
def get_profile(
    profile_id: str,
    repo: Annotated[ProfileRepository, Depends(get_profile_repository)],
) -> ProfileResponse:
    """Detalle de un perfil por id (404 si no existe)."""
    profile = repo.get(profile_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found")
    return ProfileResponse.model_validate(profile)
