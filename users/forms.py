# IMPORTS
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import Required, Email, Length, EqualTo, Regexp, ValidationError
import re


# Function which checks forbidden characters in a string
def character_check(form, field):
    excluded_characters = "*?!'^+%&/()=}][{$#@<>"
    for char in field.data:
        if char in excluded_characters:
            raise ValidationError(f"Character {char} is not allowed")

# Register form class
class RegisterForm(FlaskForm):
    # Checks for valid email address format
    email = StringField(validators=[Required(), Email()])
    # Checks if forbidden characters have been entered
    firstname = StringField(validators=[Required(), character_check])
    lastname = StringField(validators=[Required(), character_check])
    # Regex is giving the format of the field, in this case 4 digits - 3 digits - 4 digits format
    phone = StringField(validators=[Required(),
                                    Regexp(regex=r'(^\d{4}-\d{3}-\d{4}$)',
                                           message='Phone must only contain digits and dashes and '
                                                   'be of this format 1111-111-1111')])
    # Checks for length of password to be between 6 and 12 characters
    password = PasswordField(validators=[Required(), Length(min=6, max=12,
                                                            message='Password must be between 6 and 12 characters')])
    # Checks that both fields are the same
    confirm_password = PasswordField(validators=[Required(), EqualTo('password',
                                                                     message='Both password fields must be equal')])
    # Checks that the length of the pin key is 32
    pin_key = StringField(validators=[Required(), Length(max=32, min=32, message='Length of pin must be 32')])
    submit = SubmitField()

    # Custom validator which checks that the password is following the correct format
    def validate_password(self, password):
        p = re.compile(r'(?=.*\d)(?=.*[A-Z])(?=.*[a-z])(?=.*\W)')
        if not p.match(self.password.data):
            raise ValidationError("Password must contain at least 1 digit,"
                                  " 1 uppercase letter, 1 lowercase letter and one special character.")

# Login form class
class LoginForm(FlaskForm):
    # Checks for valid email address format
    username = StringField(validators=[Required(), Email()])
    password = PasswordField(validators=[Required()])
    pin = StringField(validators=[Required()])
    submit = SubmitField()
