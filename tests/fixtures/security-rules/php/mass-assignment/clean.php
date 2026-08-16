<?php
User::create($request->only(['name', 'email']));
