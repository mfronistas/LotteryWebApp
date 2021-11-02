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


class RegisterForm(FlaskForm):
    email = StringField(validators=[Required(), Email()])
    firstname = StringField(validators=[Required(), character_check])
    lastname = StringField(validators=[Required(), character_check])
    # Regex is giving the format of the field
    phone = StringField(validators=[Required(), Regexp(regex=r'(^\d{4}-\d{3}-\d{4}$)', message='Phone must only contain digits and be of this format 1111-111-1111')])
    password = PasswordField(validators=[Required(), Length(min=6, max=12, message='Password must be between 6 and 12 characters')])
    confirm_password = PasswordField(validators=[Required(), EqualTo('password', message='Both password fields must be equal')])
    pin_key = StringField(validators=[Required(), Length(max=32, min=32, message='Length of pin must be 32')])
    submit = SubmitField()

    # Custom validator which checks that the password is following the correct format
    def validate_password(self, password):
        p = re.compile(r'(?=.*\d)(?=.*[A-Z])(?=.*[a-z])(?=.*\W)')
        if not p.match(self.password.data):
            raise ValidationError("Password must contain at least 1 digit, 1 uppercase letter, 1 lowercase letter and one special character.")


class LoginForm(FlaskForm):
    username = StringField(validators=[Required(), Email()])
    password = PasswordField(validators=[Required()])
    pin = StringField(validators=[Required()])
    submit = SubmitField()