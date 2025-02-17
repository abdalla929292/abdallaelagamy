from modeltranslation.translator import translator, TranslationOptions
from .models import Ticket, Role, Position, Department, RequestType, SubRequestType, CompanySettings, SubPosition

class TicketTranslationOptions(TranslationOptions):
    fields = ('title', 'department', 'description', 'request_type', 'sub_request_type', 'assigned_to', 'applied_for', 'attachment')

translator.register(Ticket, TicketTranslationOptions)

class RoleTranslationOptions(TranslationOptions):
    fields = ('name',)

translator.register(Role, RoleTranslationOptions)

class PositionTranslationOptions(TranslationOptions):
    fields = ('name',)

translator.register(Position, PositionTranslationOptions)

class DepartmentTranslationOptions(TranslationOptions):
    fields = ('name',)

translator.register(Department, DepartmentTranslationOptions)

class RequestTypeTranslationOptions(TranslationOptions):
    fields = ('name',)

translator.register(RequestType, RequestTypeTranslationOptions)

class SubRequestTypeTranslationOptions(TranslationOptions):
    fields = ('name',)

translator.register(SubRequestType, SubRequestTypeTranslationOptions)

class CompanySettingsTranslationOptions(TranslationOptions):
    fields = ('name',)

translator.register(CompanySettings, CompanySettingsTranslationOptions)

class SubPositionTranslationOptions(TranslationOptions):
    fields = ('name',)

translator.register(SubPosition, SubPositionTranslationOptions)
