"""
Database Schemas for Civic-Sense

Each Pydantic model represents a MongoDB collection.
Collection name = lowercase of class name (User -> "user", Report -> "report").
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, Literal, List

class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    role: Literal['user', 'municipal'] = Field('user', description="Role of the account")
    password_hash: str = Field(..., description="Hashed password")
    is_active: bool = Field(True, description="Whether user is active")

class Location(BaseModel):
    lat: Optional[float] = Field(None)
    lng: Optional[float] = Field(None)
    address: Optional[str] = Field('', description="Nearest address or landmark")

class Report(BaseModel):
    user_email: str = Field(..., description="Reporter email")
    name: str = Field('Citizen', description="Reporter display name")
    description: str = Field(..., description="Issue description")
    category: str = Field('Other', description="Issue category")
    location: Location = Field(default_factory=Location)
    imageUrl: Optional[str] = Field('', description="Image URL if any")
    status: Literal['Submitted','In Review','Validated','Resolved','Rejected'] = Field('Submitted')
    timestamp: int = Field(..., description="Client timestamp (ms)")
    pointsAwarded: int = Field(0, description="Civic points awarded by server heuristics/AI")
