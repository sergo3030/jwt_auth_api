from fastapi import HTTPException, status

exceptions = {
    "credentials_exception": HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                           detail="Could not validate credentials",
                                           headers={"WWW-Authenticate": "Bearer"}),
    "login_exception": HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                     detail="Incorrect username or password",
                                     headers={"WWW-Authenticate": "Bearer"}),
    "expired_signature": HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                       detail="JWT signature has expired",
                                       headers={"WWW-Authenticate": "Bearer"}),
    "scopes_exception": HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                      detail="Not enough permissions",
                                      headers={"WWW-Authenticate": "Bearer"}),
    "user_exists": HTTPException(status_code=status.HTTP_409_CONFLICT,
                                 detail="User already exists"),
    "user_not_found": HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                    detail="User not found")
}
