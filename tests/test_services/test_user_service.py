from builtins import range
import pytest
from sqlalchemy import select
from app.dependencies import get_settings
from app.models.user_model import User
from app.services.user_service import UserService

pytestmark = pytest.mark.asyncio

# Test creating a user with valid data
async def test_create_user_with_valid_data(db_session, email_service):
    user_data = {
        "email": "valid_user@example.com",
        "password": "ValidPassword123!",
        "nickname": "newuser"  # Add required fields
    }
    user = await UserService.create(db_session, user_data, email_service)
    assert user is not None
    assert user.email == user_data["email"]

# Test creating a user with invalid data
async def test_create_user_with_invalid_data(db_session, email_service):
    user_data = {
        "nickname": "invalidname",  # Invalid nickname
        "email": "invalidemail",  # Invalid email
        "password": "short",  # Invalid password
    }
    user = await UserService.create(db_session, user_data, email_service)
    assert user is None

# Test fetching a user by ID when the user exists
async def test_get_by_id_user_exists(db_session, user):
    retrieved_user = await UserService.get_by_id(db_session, user.id)
    assert retrieved_user.id == user.id

# Test fetching a user by ID when the user does not exist
async def test_get_by_id_user_does_not_exist(db_session):
    non_existent_user_id = "non-existent-id"
    retrieved_user = await UserService.get_by_id(db_session, non_existent_user_id)
    assert retrieved_user is None

# Test fetching a user by nickname when the user exists
async def test_get_by_nickname_user_exists(db_session, user):
    retrieved_user = await UserService.get_by_nickname(db_session, user.nickname)
    assert retrieved_user.nickname == user.nickname

# Test fetching a user by nickname when the user does not exist
async def test_get_by_nickname_user_does_not_exist(db_session):
    retrieved_user = await UserService.get_by_nickname(db_session, "non_existent_nickname")
    assert retrieved_user is None

# Test fetching a user by email when the user exists
async def test_get_by_email_user_exists(db_session, user):
    retrieved_user = await UserService.get_by_email(db_session, user.email)
    assert retrieved_user.email == user.email

# Test fetching a user by email when the user does not exist
async def test_get_by_email_user_does_not_exist(db_session):
    retrieved_user = await UserService.get_by_email(db_session, "non_existent_email@example.com")
    assert retrieved_user is None

# Test updating a user with valid data
async def test_update_user_valid_data(db_session, user):
    new_email = "updated_email@example.com"
    updated_user = await UserService.update(db_session, user.id, {"email": new_email})
    assert updated_user is not None
    assert updated_user.email == new_email

# Test updating a user with invalid data
async def test_update_user_invalid_data(db_session, user):
    updated_user = await UserService.update(db_session, user.id, {"email": "invalidemail"})
    assert updated_user is None

# Test deleting a user who exists
async def test_delete_user_exists(db_session, user):
    deletion_success = await UserService.delete(db_session, user.id)
    assert deletion_success is True

# Test attempting to delete a user who does not exist
async def test_delete_user_does_not_exist(db_session):
    non_existent_user_id = "non-existent-id"
    deletion_success = await UserService.delete(db_session, non_existent_user_id)
    assert deletion_success is False

# Test listing users with pagination
async def test_list_users_with_pagination(db_session, users_with_same_role_50_users):
    users_page_1 = await UserService.list_users(db_session, skip=0, limit=10)
    users_page_2 = await UserService.list_users(db_session, skip=10, limit=10)
    assert len(users_page_1) == 10
    assert len(users_page_2) == 10
    assert users_page_1[0].id != users_page_2[0].id

# Test registering a user with valid data
async def test_register_user_with_valid_data(db_session, email_service):
    user_data = {
        "email": "register_valid_user@example.com",
        "password": "RegisterValid123!",
        "nickname": "newuser"  # Add required fields
    }
    user = await UserService.register_user(db_session, user_data, email_service)
    assert user is not None
    assert user.email == user_data["email"]

# Test attempting to register a user with invalid data
async def test_register_user_with_invalid_data(db_session, email_service):
    user_data = {
        "email": "registerinvalidemail",  # Invalid email
        "password": "short",  # Invalid password
    }
    user = await UserService.register_user(db_session, user_data, email_service)
    assert user is None

# Test successful user login
async def test_login_user_successful(db_session, verified_user):
    user_data = {
        "email": verified_user.email,
        "password": "MySuperPassword$1234",
    }
    logged_in_user = await UserService.login_user(db_session, user_data["email"], user_data["password"])
    assert logged_in_user is not None

# Test user login with incorrect email
async def test_login_user_incorrect_email(db_session):
    user = await UserService.login_user(db_session, "nonexistentuser@noway.com", "Password123!")
    assert user is None

# Test user login with incorrect password
async def test_login_user_incorrect_password(db_session, user):
    user = await UserService.login_user(db_session, user.email, "IncorrectPassword!")
    assert user is None

# Test account lock after maximum failed login attempts
async def test_account_lock_after_failed_logins(db_session, verified_user):
    max_login_attempts = get_settings().max_login_attempts
    for _ in range(max_login_attempts):
        await UserService.login_user(db_session, verified_user.email, "wrongpassword")
    
    is_locked = await UserService.is_account_locked(db_session, verified_user.email)
    assert is_locked, "The account should be locked after the maximum number of failed login attempts."

# Test resetting a user's password
async def test_reset_password(db_session, user):
    new_password = "NewPassword123!"
    reset_success = await UserService.reset_password(db_session, user.id, new_password)
    assert reset_success is True

# Test verifying a user's email
async def test_verify_email_with_token(db_session, user):
    token = "valid_token_example"  # This should be set in your user setup if it depends on a real token
    user.verification_token = token  # Simulating setting the token in the database
    await db_session.commit()
    result = await UserService.verify_email_with_token(db_session, user.id, token)
    assert result is True

# Test unlocking a user's account
async def test_unlock_user_account(db_session, locked_user):
    unlocked = await UserService.unlock_user_account(db_session, locked_user.id)
    assert unlocked, "The account should be unlocked"
    refreshed_user = await UserService.get_by_id(db_session, locked_user.id)
    assert not refreshed_user.is_locked, "The user should no longer be locked"

# Test creating a user with an email that already exists
async def test_create_user_with_existing_email(db_session, email_service, user):
    user_data = {
        "email": user.email,  # Using existing email
        "password": "ValidPassword123!",
        "nickname": "unique_nickname"
    }
    new_user = await UserService.create(db_session, user_data, email_service)
    assert new_user is None, "Should not create user with existing email"

# Test creating a user with a nickname that already exists
async def test_create_user_with_existing_nickname(db_session, email_service, user):
    user_data = {
        "email": "new_user@example.com",
        "password": "ValidPassword123!",
        "nickname": user.nickname  # Using existing nickname
    }
    new_user = await UserService.create(db_session, user_data, email_service)
    assert new_user is None, "Should not create user with existing nickname"



# Test login with unverified email
async def test_login_with_unverified_email(db_session, user):
    # Ensure user is unverified
    user.email_verified = False
    await db_session.commit()
    
    result = await UserService.login_user(db_session, user.email, "MySuperPassword$1234")
    assert result is None, "Unverified users should not be able to log in"

# Test login with locked account
async def test_login_with_locked_account(db_session, user):
    # Lock the user account
    user.is_locked = True
    await db_session.commit()
    
    result = await UserService.login_user(db_session, user.email, "MySuperPassword$1234")
    assert result is None, "Locked users should not be able to log in"

# Test user count method
async def test_user_count(db_session, users_with_same_role_50_users):
    count = await UserService.count(db_session)
    assert count == 50, "User count should match the number of users in the database"

# Test reset password for non-existent user
async def test_reset_password_nonexistent_user(db_session):
    non_existent_user_id = "non-existent-id"
    result = await UserService.reset_password(db_session, non_existent_user_id, "NewPassword123!")
    assert result is False, "Should not reset password for non-existent user"

# Test verifying email with invalid token
async def test_verify_email_with_invalid_token(db_session, user):
    # Set the real token
    user.verification_token = "real_token"
    await db_session.commit()
    
    # Try to verify with wrong token
    result = await UserService.verify_email_with_token(db_session, user.id, "wrong_token")
    assert result is False, "Should not verify email with invalid token"

# Test unlocking a user's account that is not locked
async def test_unlock_already_unlocked_account(db_session, user):
    # Ensure user is unlocked
    user.is_locked = False
    await db_session.commit()
    
    result = await UserService.unlock_user_account(db_session, user.id)
    assert result is False, "Should return False when trying to unlock an already unlocked account"

# Test login tracks last_login_at
async def test_login_updates_last_login_timestamp(db_session, verified_user):
    # Log in the user
    logged_in_user = await UserService.login_user(
        db_session, 
        verified_user.email, 
        "MySuperPassword$1234"
    )
    
    assert logged_in_user is not None
    assert logged_in_user.last_login_at is not None, "Login should set last_login_at timestamp"
    
    # If you need to test that it updates on subsequent logins:
    original_timestamp = logged_in_user.last_login_at
    
    # Wait a moment to ensure timestamp changes
    import asyncio
    await asyncio.sleep(0.1)
    
    # Log in again
    logged_in_again = await UserService.login_user(
        db_session, 
        verified_user.email, 
        "MySuperPassword$1234"
    )
    
    assert logged_in_again is not None
    assert logged_in_again.last_login_at > original_timestamp, "Subsequent login should update last_login_at timestamp"

# Test login resets failed_login_attempts counter
async def test_successful_login_resets_failed_attempts(db_session, verified_user):
    # Set some failed attempts
    verified_user.failed_login_attempts = 2
    await db_session.commit()
    
    # Log in successfully
    logged_in_user = await UserService.login_user(
        db_session, 
        verified_user.email, 
        "MySuperPassword$1234"
    )
    
    assert logged_in_user is not None
    assert logged_in_user.failed_login_attempts == 0, "Successful login should reset failed attempts"
