const express = require("express");
const router = express.Router();

// load controller
const {
	register,
	login,
	openAccess,
	restrictedAccess
} = require("../../../controllers/user_controller");

// middlewares
let { catchErrors } = require("../../../config/errorHandler");
let { userRegisterValidation } = require("../../../middlewares/validations");
let { allAuth, adminAuth } = require("../../../middlewares/auth");

// routes
router.post("/", userRegisterValidation, catchErrors(register));
router.post("/login", catchErrors(login));
router.get("/open", allAuth, catchErrors(openAccess));
router.get("/admin", adminAuth, catchErrors(restrictedAccess));

// export router
module.exports = router;
