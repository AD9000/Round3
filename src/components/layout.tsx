import React from "react"

import { Header } from "./Sidebar/Header"

import Footer from "./footer"
import "./global.css"

const Layout = ({ location, title, children }) => {
  return (
    <div
      style={{
        backgroundColor: "var(--bg)",
        color: "var(--textNormal)",
        transition: "color 0.2s ease-out, background 0.2s ease-out",
        minHeight: "100vh",
      }}
    >
      <div className="sidebar">
        <div
          className="lg:h-screen p-4 flex flex-col justify-center items-center"
          style={{ minHeight: 200 }}
        >
          <Header title={title} />
        </div>
      </div>

      <div className="main-content">
        <main>{children}</main>
        <Footer />
      </div>
    </div>
  )
}

export default Layout
