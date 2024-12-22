import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";

const createTokens = async (userId) => {
    try {
        const currentUser = await User.findById(userId);
        const tokenData = {
            accessToken: currentUser.generateAccessToken(),
            refreshToken: currentUser.generateRefreshToken(),
        };

        currentUser.accessToken = tokenData.accessToken;
        currentUser.refreshToken = tokenData.refreshToken;

        await currentUser.save({ validateBeforeSave: false });

        return tokenData;
    } catch (err) {
        throw new ApiError(500, "Failed to generate tokens");
    }
};

const createUser = asyncHandler(async (req, res) => {
    const { fullName, email, username, password } = req.body;

    if ([fullName, email, username, password].some((field) => !field?.trim())) {
        throw new ApiError(400, "All fields are required for registration");
    }

    const existingUser = await User.findOne({
        $or: [{ email }, { username }],
    });

    if (existingUser) {
        throw new ApiError(409, "User already exists with provided email or username");
    }

    const newUser = await User.create({
        fullName,
        email,
        password,
        username: username.toLowerCase(),
    });

    const sanitizedUser = await User.findById(newUser._id).select("-password -refreshToken");

    if (!sanitizedUser) {
        throw new ApiError(500, "Error occurred while registering user");
    }

    res.status(201).json(new ApiResponse(201, sanitizedUser, "User registered successfully"));
});

const authenticateUser = asyncHandler(async (req, res) => {
    const { email, username, password } = req.body;

    if (!email && !username) {
        throw new ApiError(400, "Email or username is required");
    }

    const foundUser = await User.findOne({
        $or: [{ email }, { username }],
    });

    if (!foundUser) {
        throw new ApiError(404, "User not found");
    }

    const validPassword = await foundUser.isPasswordCorrect(password);

    if (!validPassword) {
        throw new ApiError(401, "Invalid credentials");
    }

    const { accessToken, refreshToken } = await createTokens(foundUser._id);
    const userDetails = await User.findById(foundUser._id).select("-password -refreshToken");

    res
        .status(200)
        .cookie("accessToken", accessToken, { httpOnly: true, secure: true })
        .cookie("refreshToken", refreshToken, { httpOnly: true, secure: true })
        .json(new ApiResponse(200, { user: userDetails, accessToken, refreshToken }, "Login successful"));
});

const signOutUser = asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(req.user._id, { refreshToken: undefined }, { new: true });

    res
        .status(200)
        .clearCookie("accessToken", { httpOnly: true, secure: true })
        .clearCookie("refreshToken", { httpOnly: true, secure: true })
        .json(new ApiResponse(200, {}, "Logged out successfully"));
});

const renewAccessToken = asyncHandler(async (req, res) => {
    const tokenFromRequest =
        req.cookies?.refreshToken || req.body?.refreshToken || req.query?.refreshToken;

    if (!tokenFromRequest) {
        throw new ApiError(401, "Unauthorized: Refresh token missing");
    }

    const decoded = jwt.verify(tokenFromRequest, process.env.REFRESH_TOKEN_SECRET);
    const user = await User.findById(decoded._id);

    if (tokenFromRequest !== user?.refreshToken) {
        throw new ApiError(401, "Invalid or expired refresh token");
    }

    const { accessToken, refreshToken: newRefreshToken } = await createTokens(user._id);

    res
        .status(200)
        .cookie("accessToken", accessToken, { httpOnly: true, secure: true })
        .cookie("refreshToken", newRefreshToken, { httpOnly: true, secure: true })
        .json(new ApiResponse(200, { accessToken, refreshToken: newRefreshToken }, "Token refreshed"));
});

export { createUser, authenticateUser, signOutUser, renewAccessToken };
