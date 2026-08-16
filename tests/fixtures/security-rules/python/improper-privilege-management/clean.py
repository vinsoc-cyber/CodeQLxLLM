def update_user(request, user):
    user.is_superuser = False
    user.save()
