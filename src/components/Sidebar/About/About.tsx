import React from "react"
import { Link, makeStyles, Theme } from "@material-ui/core"
import GitHubIcon from "@material-ui/icons/GitHub"
import LinkedInIcon from "@material-ui/icons/LinkedIn"

const useStyles = makeStyles((theme: Theme) => ({
  dock: {
    padding: "10px",
    display: "flex",
    flex: 1,
    backgroundColor: "transparent",
  },
  aboutLink: {
    boxShadow: "none",
  },
  dockIcon: {
    color: "var(--textNormal)",
    fontSize: "60px",
    margin: "15px 10px",
    transition: "transform 0.2s",

    "&:hover": {
      transform: "scale(1.3)",
    },
  },
}))

const About = () => {
  const classes = useStyles()

  return (
    <div>
      <div className={classes.dock}>
        <Link
          href="https://github.com/AD9000"
          target="_blank"
          rel="noopener"
          className={classes.aboutLink}
        >
          <GitHubIcon className={classes.dockIcon} />
        </Link>

        <Link
          href="https://www.linkedin.com/in/atharv-damle"
          target="_blank"
          rel="noopener"
          className={classes.aboutLink}
        >
          <LinkedInIcon className={classes.dockIcon} />
        </Link>
      </div>
    </div>
  )
}

export { About }
