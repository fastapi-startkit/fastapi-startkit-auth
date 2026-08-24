from fastapi_startkit.fastapi import Router

from app.http.controllers import auth_controller, dashboard_controller

router = Router()
router.get("/", dashboard_controller.home)
router.get("/login", auth_controller.create)
router.post("/login", auth_controller.store)
router.get("/dashboard", dashboard_controller.index)
router.post("/logout", auth_controller.destroy)
