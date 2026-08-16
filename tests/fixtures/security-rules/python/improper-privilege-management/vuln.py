def update_user(request, user):
    user.is_superuser = request.POST.get("is_superuser")
    user.save()
