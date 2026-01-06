// slices/apslice.js
import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';
import { Base_URL } from '../constant';

const baseQuery = fetchBaseQuery({ 
    baseUrl: Base_URL,
    credentials: 'include', // Send cookies with requests for authentication
    prepareHeaders: (headers, { getState }) => {
        // Get token from Redux auth state
        const token = getState()?.auth?.userInfo?.token;
        
        // If token exists, add to Authorization header
        if (token) {
            headers.set('Authorization', `Bearer ${token}`);
        }
        
        return headers;
    },
});

export const apiSlice = createApi({
    baseQuery,
    tagTypes: ['Products', 'Orders', 'Users', 'Settings', 'Upload'],
    endpoints: () => ({}),
});